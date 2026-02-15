import base64
import json
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, generics
from django.utils import timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.exceptions import InvalidSignature
from django.conf import settings
from datetime import datetime, timedelta
import pytz
from .models import DeviceMessage
from .serializers import DeviceMessageListSerializer
from dateutil import parser as date_parser

from apps.device_management.models import Device, DeviceStatus


# Create your views here.
class DeviceMessageView(APIView):
    """
    API endpoint for devices to send authenticated messages.
    
    Expected headers:
    - X-Device-Certificate: Base64-encoded PEM certificate
    - X-Device-Signature: Base64-encoded signature of message body
    """
    permission_classes = []  # Disable default authentication - uses certificate auth
    
    def post(self, request):
        # Extract headers
        cert_header = request.headers.get('X-Device-Certificate')
        signature_header = request.headers.get('X-Device-Signature')

        if not cert_header or not signature_header:
            return Response({'error': 'Missing required headers.'}, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            # Decode and load certificate
            cert_pem = base64.b64decode(cert_header)
            device_cert = x509.load_pem_x509_certificate(cert_pem)
        except Exception as e:
            return Response({'error': f'Invalid certificate format: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Decode signature
            signature = base64.b64decode(signature_header)
        except Exception as e:
            return Response({'error': f'Invalid signature format: {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Validate certificate
        try:
            with open(settings.CA_CERTIFICATE_PATH, 'rb') as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
        except Exception as e:
            return Response(
                {'error': 'Server configuration error'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Verify certificate is signed by CA
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                device_cert.signature,
                device_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                device_cert.signature_hash_algorithm,
            )
        except InvalidSignature:
            return Response({'error': 'Invalid device certificate.'}, status=status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            return Response({'error': 'Certificate verification failed.'}, status=status.HTTP_401_UNAUTHORIZED)

        # Check certificate expiry
        now = datetime.utcnow().replace(tzinfo=pytz.UTC)
        cert_not_before = device_cert.not_valid_before.replace(tzinfo=pytz.UTC)
        cert_not_after = device_cert.not_valid_after.replace(tzinfo=pytz.UTC)
        
        if cert_not_before > now or cert_not_after < now:
            return Response(
                {'error': 'Certificate expired or not yet valid'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Extract device ID from certificate Common Name
        try:
            common_name = device_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            device_id = common_name
        except Exception as e:
            return Response(
                {'error': 'Invalid certificate'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Look up device in database
        try:
            device = Device.objects.get(id=device_id)
        except Device.DoesNotExist:
            return Response(
                {'error': 'Device not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check device status
        if device.status == DeviceStatus.REVOKED:
            return Response(
                {'error': 'Device certificate has been revoked'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        # Get request body (the message being sent)
        try:
            message_body = request.body
            if not message_body:
                return Response(
                    {'error': 'Empty message body'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except Exception as e:
            return Response(
                {'error': 'Could not read message body'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Verify signature of message body using device's public key
        try:
            device_public_key = device_cert.public_key()

            # Verify signature based on key type (RSA or ECDSA)
            if isinstance(device_public_key, rsa.RSAPublicKey):
                # RSA signature verification
                device_public_key.verify(
                    signature,
                    message_body,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
            elif isinstance(device_public_key, ec.EllipticCurvePublicKey):
                # ECDSA signature verification
                device_public_key.verify(
                    signature,
                    message_body,
                    ec.ECDSA(hashes.SHA256())
                )
            else:
                # Unknown key type
                return Response(
                    {'error': 'Unsupported certificate algorithm'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except InvalidSignature:
            return Response(
                {'error': 'Invalid message signature'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            return Response(
                {'error': f'Signature verification failed: {str(e)}'},
                status=status.HTTP_401_UNAUTHORIZED
            )
        
        # Parse JSON message
        try:
            message_data = json.loads(message_body)
        except json.JSONDecodeError:
            return Response(
                {'error': 'Invalid JSON in message body'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Code below was copied from https://www.geeksforgeeks.org/python/get-user-ip-address-in-django/
        # Extract client IP address
        # START OF COPIED CODE
        def get_client_ip(request):
            ip_address = request.META.get('HTTP_X_FORWARDED_FOR')
            if ip_address:
                ip_address = ip_address.split(',')[0]
            else:
                ip_address = request.META.get('REMOTE_ADDR')
            return ip_address
        # END OF COPIED CODE

        client_ip = get_client_ip(request)

        # Extract timestamp from message data
        message_timestamp = message_data.get('timestamp')
        if message_timestamp:
            try:
                parsed_timestamp = date_parser.isoparse(message_timestamp)
            except Exception as e:
                parsed_timestamp = timezone.now()
        else:
            parsed_timestamp = timezone.now()

        #Extract certificate serial number
        cert_serial_number = hex(device_cert.serial_number)[2:]

        # Save message to database
        saved_successfully = False

        # Try to save the message
        try:
            DeviceMessage.objects.create(
                device=device,
                message_type=message_data.get('message_type', 'unknown'),
                timestamp=parsed_timestamp,
                data=message_data.get('data', {}),
                ip_address=client_ip,
                certificate_serial=cert_serial_number
            )
            saved_successfully = True
        except Exception as e:
            print(f'error: Failed to store message: {str(e)}')
        
        # Update device status to ACTIVE if it was PENDING or INACTIVE
        if device.status in [DeviceStatus.PENDING, DeviceStatus.INACTIVE]:
            device.status = DeviceStatus.ACTIVE
            device.save()
        
        response_data = {
            'status': 'success',
            'saved': saved_successfully,
            'device_id': device.id,
            'timestamp': timezone.now().isoformat()
        }

        if saved_successfully:
            response_data['message'] = 'Message stored successfully.'
        else:
            response_data['message'] = 'Failed to store message.'

        return Response(response_data, status=status.HTTP_200_OK)


class DeviceMessageListView(generics.ListAPIView):
    """
    API endpoint for retrieving device messages with filtering.

    GET /api/v1/messages/

    Query Parameters:
    - message_type: Filter by message type (e.g., "alert", "heartbeat")
    - time_window: Filter by time window ("1h", "24h", "7d", "all")
    - limit: Number of messages to return (default: 50, max: 200)

    Example:
    GET /api/v1/messages/?message_type=alert&time_window=24h&limit=50

    Returns messages ordered by received_at (newest first).
    """
    serializer_class = DeviceMessageListSerializer
    permission_classes = []  # Public endpoint (can be restricted later)
    pagination_class = None  # Disable DRF pagination, use custom limit parameter instead

    def get_queryset(self):
        """
        Filter messages based on query parameters.
        """
        queryset = DeviceMessage.objects.select_related('device').all()

        # Filter by message type
        message_type = self.request.query_params.get('message_type', None)
        if message_type:
            queryset = queryset.filter(message_type=message_type)

        # Filter by time window
        time_window = self.request.query_params.get('time_window', '24h')
        if time_window != 'all':
            now = timezone.now()
            time_mapping = {
                '1h': timedelta(hours=1),
                '6h': timedelta(hours=6),
                '24h': timedelta(hours=24),
                '7d': timedelta(days=7),
            }

            if time_window in time_mapping:
                start_time = now - time_mapping[time_window]
                queryset = queryset.filter(recieved_at__gte=start_time)

        # Limit results (default: 50, max: 200)
        limit = self.request.query_params.get('limit', 50)
        try:
            limit = min(int(limit), 200)
        except (ValueError, TypeError):
            limit = 50

        return queryset.order_by('-recieved_at')[:limit]