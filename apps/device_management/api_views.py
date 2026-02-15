"""
API views for device management.
File: apps/device_management/api_views.py

Uses DRF ViewSets for full CRUD operations on devices.
"""

from rest_framework import viewsets, status, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter
from django.http import HttpResponse

from apps.device_management.models import Device, DeviceStatus
from apps.device_management.serializers import (
    DeviceListSerializer,
    DeviceDetailSerializer,
    DeviceRegistrationSerializer,
    )
from django.utils import timezone
from datetime import timedelta
from apps.device_management.utils import generate_device_certificate
from apps.device_management.views import _generate_config_h
import io
import zipfile
from pathlib import Path


class DeviceCodeDownloadSerializer(serializers.Serializer):
    """
    Serializer for WiFi credentials input when downloading device code bundle.

    These credentials are NOT stored on the server - they are only embedded
    in the generated config.h file for the device to use.
    """
    wifi_ssid = serializers.CharField(
        max_length=32,
        required=True,
        help_text="WiFi network name (SSID). Maximum 32 characters."
    )
    wifi_password = serializers.CharField(
        max_length=64,
        required=True,
        help_text="WiFi password. Maximum 64 characters."
    )


class PublicDeviceViewSet(viewsets.ReadOnlyModelViewSet):
    """
    Public read-only access to all devices.
    
    Endpoints:
    - GET /api/v1/devices/public/           - List all devices (paginated)
    - GET /api/v1/devices/public/{id}/      - Device detail
    
    Features:
    - No authentication required
    - Filtering by status, device_type
    - Searching by name, location
    - Ordering by created_at, updated_at, name
    - Pagination (25 per page)
    
    Examples:
    - /api/v1/devices/public/?status=ACTIVE
    - /api/v1/devices/public/?search=ESP32
    - /api/v1/devices/public/?ordering=-created_at
    """
    permission_classes = [AllowAny]
    queryset = Device.objects.select_related('created_by').all()
    
    # Enable filtering, searching, ordering
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['status', 'device_type']
    search_fields = ['name', 'latitude', 'longitude']
    ordering_fields = ['created_at', 'updated_at', 'name']
    ordering = ['-created_at']  # Default: newest first

    def get_serializer_class(self):
        """Use detailed serializer for single device, list serializer for list."""
        if self.action == 'retrieve':
            return DeviceDetailSerializer
        return DeviceListSerializer
    
class ParticipantDeviceViewSet(viewsets.ModelViewSet):
    """
    CRUD operations for participant's own devices.
    
    Endpoints:
    - GET /api/v1/devices/participant/           - List user devices
    - GET /api/v1/devices/participant/{id}/      - Get device detail
    - POST /api/v1/devices/participant/          - Register new device
    - PATCH /api/v1/devices/participant/{id}/    - Update device
    - DELETE /api/v1/devices/participant/{id}/   - Revoke device
    """
    permission_classes = [IsAuthenticated]
    
    # Filtering, searching, ordering (same as public)
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ['status', 'device_type']
    search_fields = ['name', 'latitude', 'longitude']
    ordering_fields = ['created_at', 'updated_at', 'name']
    ordering = ['-created_at']

    def get_queryset(self):
        """Return only devices owned by the current user."""
        return Device.objects.filter(
            created_by=self.request.user
        ).select_related('created_by')

    def get_serializer_class(self):
        """Use different serializers for different actions."""
        if self.action == 'list':
            return DeviceListSerializer
        elif self.action == 'retrieve':
            return DeviceDetailSerializer
        elif self.action == 'create':
            return DeviceRegistrationSerializer
        return DeviceRegistrationSerializer

    def perform_create(self, serializer):
        """
        Set the device owner to the current user on creation.
        
        Why: Participants should not be able to specify who owns the device.
        The owner is always the authenticated user making the request.
        This prevents users from creating devices under other accounts.
        """
        serializer.save(created_by=self.request.user)


    def destroy(self, request, *args, **kwargs):
        """
        Soft delete: Set device status to REVOKED instead of deleting.
        
        Why: Never hard-delete devices for audit trail and security reasons.
        - Preserves message history linked to this device
        - Allows admins to investigate revoked devices
        - Prevents certificate reuse if device was compromised
        - Returns 200 with device data (not 204) so frontend can show confirmation
        """
        device = self.get_object()
        device.status = DeviceStatus.REVOKED
        device.save()
        
        serializer = DeviceDetailSerializer(device)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='generate-certificate')
    def generate_certificate(self, request, pk=None):
        """
        Generate X.509 certificate and private key for a device.
        
        Why: Certificates enable secure device-to-server communication.
        - POST required because this creates new cryptographic material
        - Returns metadata only (expiry, download window) - not the actual keys
        - Keys are downloaded separately via dedicated endpoints for security
        - 24-hour download window limits exposure if session is compromised
        - Revoked devices cannot generate new certificates
        """
        device = self.get_object()
        
        # Prevent certificate generation for revoked devices
        if device.status == DeviceStatus.REVOKED:
            return Response(
                {'error': 'Cannot generate certificate for a revoked device.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Generate certificate using existing utility function
            cert_pem, key_pem, serial_hex, expiry_date = generate_device_certificate(device)
            
            # Store certificate data on device
            device.certificate_pem = cert_pem
            device.private_key_pem = key_pem
            device.certificate_serial = serial_hex
            device.certificate_expiry = expiry_date
            device.certificate_generated_at = timezone.now()
            device.save()
            
            # Return certificate metadata (not the actual keys)
            return Response({
                'message': 'Certificate generated successfully.',
                'certificate_serial': serial_hex,
                'certificate_expiry': expiry_date.isoformat(),
                'download_expires_at': (timezone.now() + timedelta(hours=24)).isoformat(),
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response(
                {'error': f'Failed to generate certificate: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    @action(detail=True, methods=['get'], url_path='download-certificate')
    def download_certificate(self, request, pk=None):
        """
        Download the device's X.509 certificate as a .pem file.
        
        Why: Separate download endpoint from generation for security.
        - GET because retrieving existing data, not creating
        - 24-hour window limits exposure if user session is compromised
        - Returns actual file (not JSON) for easy device configuration
        - Certificate is public key - safe to download multiple times
        """
        device = self.get_object()
        
        # Check if certificate exists
        if not device.certificate_pem or not device.certificate_generated_at:
            return Response(
                {'error': 'No certificate available. Please generate one first.'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check 24-hour download window
        expiry_window = device.certificate_generated_at + timedelta(hours=24)
        if timezone.now() > expiry_window:
            return Response(
                {'error': 'Download window expired. Please regenerate the certificate.'},
                status=status.HTTP_410_GONE
            )
        
        # Return certificate as downloadable file
        response = HttpResponse(device.certificate_pem, content_type='application/x-pem-file')
        response['Content-Disposition'] = f'attachment; filename="{device.name}_certificate.pem"'
        return response
    
    @action(detail=True, methods=['get'], url_path='download-private-key')
    def download_private_key(self, request, pk=None):
        """
        Download the device's private key as a .key file.
        
        Why: Private key must be downloaded separately from certificate.
        - GET because retrieving existing data, not creating
        - 24-hour window enforced strictly - private keys are sensitive
        - Returns actual file (not JSON) for easy device configuration
        - Private key should only be downloaded once and stored securely on device
        - After download window expires, certificate must be regenerated
        """
        device = self.get_object()
        
        # Check if private key exists
        if not device.private_key_pem or not device.certificate_generated_at:
            return Response(
                {'error': 'No private key available. Please generate a certificate first.'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Check 24-hour download window
        expiry_window = device.certificate_generated_at + timedelta(hours=24)
        if timezone.now() > expiry_window:
            return Response(
                {'error': 'Download window expired. Please regenerate the certificate.'},
                status=status.HTTP_410_GONE
            )
        
        # Return private key as downloadable file
        response = HttpResponse(device.private_key_pem, content_type='application/x-pem-file')
        response['Content-Disposition'] = f'attachment; filename="{device.name}_private.key"'
        return response

    @action(detail=True, methods=['post'], url_path='download-code')
    def download_code(self, request, pk=None):
        """
        Download complete device code bundle (Arduino sketch + config).

        Generates a ZIP file containing:
        - README.md with setup instructions
        - ESP8266_P256/config.h with device-specific configuration:
          - WiFi credentials (from request body)
          - Device UUID and certificate
          - Private key as C uint8_t array
          - Server URL and hardware pin mappings
        - ESP8266_P256/*.ino/*.h/*.cpp - Arduino sketch templates

        Request Body:
        ```json
        {
          "wifi_ssid": "MyNetwork",        // Required, max 32 chars
          "wifi_password": "SecurePass123"  // Required, max 64 chars
        }
        ```

        Security:
        - Requires authentication + device ownership
        - Certificate must exist and be within 24-hour download window
        - WiFi credentials are NOT stored on server (only embedded in config.h)

        Response:
        - Success: Binary ZIP file with Content-Disposition header
        - 400 Bad Request: Missing certificate or invalid WiFi credentials
        - 410 Gone: Download window expired (must regenerate certificate)

        References:
        - NIST SP 800-57: Key Management (justifies 24-hour private key exposure)
        - Django template equivalent: apps/device_management/views.py:download_device_code
        """
        device = self.get_object()

        # Validate request body
        serializer = DeviceCodeDownloadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {'error': 'Invalid WiFi credentials', 'field_errors': serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

        wifi_ssid = serializer.validated_data['wifi_ssid']
        wifi_password = serializer.validated_data['wifi_password']

        # Check if certificate exists
        if not device.certificate_pem or not device.private_key_pem:
            return Response(
                {'error': 'No certificate available. Please generate a certificate first.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check 24-hour download window
        if not device.certificate_generated_at:
            return Response(
                {'error': 'No certificate available. Please generate a certificate first.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        expiry_window = device.certificate_generated_at + timedelta(hours=24)
        if timezone.now() > expiry_window:
            return Response(
                {
                    'error': 'Certificate download window expired.',
                    'detail': 'Certificates are only downloadable for 24 hours after generation.',
                    'action_required': 'regenerate_certificate'
                },
                status=status.HTTP_410_GONE
            )

        try:
            # Generate config.h with WiFi credentials
            config_content = _generate_config_h(device, wifi_ssid, wifi_password)

            # Prepare paths
            BASE_DIR = Path(__file__).resolve().parent.parent.parent
            DEVICE_TEMPLATES_DIR = BASE_DIR / 'apps' / 'device_management' / 'device_templates' / 'ESP8266_sensor' / 'ESP8266_P256'
            README_PATH = DEVICE_TEMPLATES_DIR.parent / 'README.md'

            # Create in-memory ZIP
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add README.md
                if README_PATH.exists():
                    zip_file.write(README_PATH, 'README.md')

                # Add generated config.h
                zip_file.writestr('ESP8266_P256/config.h', config_content)

                # Add all template files except config.h
                if DEVICE_TEMPLATES_DIR.exists():
                    for file_path in DEVICE_TEMPLATES_DIR.iterdir():
                        if file_path.is_file() and file_path.name != 'config.h':
                            zip_file.write(file_path, f'ESP8266_P256/{file_path.name}')

            # Sanitize device name for filename
            safe_name = "".join(c for c in device.name if c.isalnum() or c in (' ', '-', '_')).strip()

            # Return ZIP as downloadable response
            zip_buffer.seek(0)
            response = HttpResponse(zip_buffer.read(), content_type='application/zip')
            response['Content-Disposition'] = f'attachment; filename="{safe_name}_ESP8266_code.zip"'
            return response

        except Exception as e:
            return Response(
                {'error': f'Failed to generate code bundle: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )