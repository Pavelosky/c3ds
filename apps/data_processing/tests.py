from django.test import TestCase, Client
from django.contrib.auth.models import User
from apps.device_management.models import Device, DeviceStatus
from apps.data_processing.models import DeviceMessage
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import json
import base64

# Create your tests here.

class DeviceMessageAPITest(TestCase):
    """Test suite for Device Message API authentication and storage"""
    
    @classmethod
    def setUpTestData(cls):
        """Set up CA for all tests"""
        from django.core.management import call_command
        from django.conf import settings
        import os
        
        if not os.path.exists(settings.CA_CERTIFICATE_PATH):
            call_command('create_ca')
    
    def setUp(self):
        """Set up test data for each test"""
        self.client = Client()
        self.url = '/api/device/message/'
        
        # Create user and device
        self.user = User.objects.create_user(username='testadmin', password='testpass')
        self.device = Device.objects.create(name='Test API Device', created_by=self.user)

    def test_successful_message_submission(self):
        """Test that a valid certificate and signature results in saved message"""
        from apps.device_management.utils import generate_device_certificate
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        
        # Generate certificate for device
        cert_pem, key_pem, serial_hex, expiry_date = generate_device_certificate(self.device)
        
        # Update device with certificate
        self.device.certificate_pem = cert_pem
        self.device.certificate_serial = serial_hex
        self.device.certificate_expiry = expiry_date
        self.device.status = DeviceStatus.ACTIVE
        self.device.save()
        
        # Create message to send
        message_data = {
            'message_type': 'heartbeat',
            'timestamp': '2024-12-13T10:30:00Z',
            'data': {'status': 'online', 'battery': 85}
        }
        message_body = json.dumps(message_data).encode('utf-8')
        
        # Load private key to sign message
        private_key = serialization.load_pem_private_key(
            key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        # Sign the message
        signature = private_key.sign(
            message_body,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Encode headers
        cert_header = base64.b64encode(cert_pem.encode('utf-8')).decode('utf-8')
        signature_header = base64.b64encode(signature).decode('utf-8')
        
        # Send request
        response = self.client.post(
            self.url,
            data=message_body,
            content_type='application/json',
            HTTP_X_DEVICE_CERTIFICATE=cert_header,
            HTTP_X_DEVICE_SIGNATURE=signature_header
        )
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()['saved'])
        
        # Verify message was saved
        self.assertEqual(DeviceMessage.objects.count(), 1)
        saved_message = DeviceMessage.objects.first()
        self.assertEqual(saved_message.device, self.device)
        self.assertEqual(saved_message.message_type, 'heartbeat')

        print("Test successful message submission PASSED.")

    def test_missing_headers(self):
        """Test that missing authentication headers returns 401"""
        message_data = {'message_type': 'test', 'timestamp': '2024-12-13T10:30:00Z', 'data': {}}
        
        # Request without headers
        response = self.client.post(
            self.url,
            data=json.dumps(message_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 401)
        self.assertIn('error', response.json())

        print("Test missing headers PASSED.")

    def test_revoked_device_rejected(self):
        """Test that revoked devices cannot send messages"""
        from apps.device_management.utils import generate_device_certificate
        from cryptography.hazmat.backends import default_backend
        
        # Generate certificate
        cert_pem, key_pem, serial_hex, expiry_date = generate_device_certificate(self.device)
        self.device.certificate_pem = cert_pem
        self.device.certificate_serial = serial_hex
        self.device.certificate_expiry = expiry_date
        self.device.status = DeviceStatus.REVOKED  # Set to REVOKED
        self.device.save()
        
        # Create and sign message
        message_data = {'message_type': 'test', 'timestamp': '2024-12-13T10:30:00Z', 'data': {}}
        message_body = json.dumps(message_data).encode('utf-8')
        
        private_key = serialization.load_pem_private_key(
            key_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        
        signature = private_key.sign(message_body, padding.PKCS1v15(), hashes.SHA256())
        
        # Send request
        cert_header = base64.b64encode(cert_pem.encode('utf-8')).decode('utf-8')
        signature_header = base64.b64encode(signature).decode('utf-8')
        
        response = self.client.post(
            self.url,
            data=message_body,
            content_type='application/json',
            HTTP_X_DEVICE_CERTIFICATE=cert_header,
            HTTP_X_DEVICE_SIGNATURE=signature_header
        )
        
        # Should be rejected with 403
        self.assertEqual(response.status_code, 403)
        self.assertIn('revoked', response.json()['error'].lower())

        print("Test revoked device rejected PASSED.")

    def test_invalid_signature_rejected(self):
        """Test that messages with invalid signatures are rejected"""
        from apps.device_management.utils import generate_device_certificate
        
        # Generate certificate
        cert_pem, key_pem, serial_hex, expiry_date = generate_device_certificate(self.device)
        self.device.certificate_pem = cert_pem
        self.device.certificate_serial = serial_hex
        self.device.certificate_expiry = expiry_date
        self.device.status = DeviceStatus.ACTIVE
        self.device.save()
        
        # Create message
        message_data = {'message_type': 'test', 'timestamp': '2024-12-13T10:30:00Z', 'data': {}}
        message_body = json.dumps(message_data).encode('utf-8')
        
        # Create INVALID signature (just random bytes)
        fake_signature = b'this_is_not_a_valid_signature'
        
        # Send request with invalid signature
        cert_header = base64.b64encode(cert_pem.encode('utf-8')).decode('utf-8')
        signature_header = base64.b64encode(fake_signature).decode('utf-8')
        
        response = self.client.post(
            self.url,
            data=message_body,
            content_type='application/json',
            HTTP_X_DEVICE_CERTIFICATE=cert_header,
            HTTP_X_DEVICE_SIGNATURE=signature_header
        )
        
        # Should be rejected with 401
        self.assertEqual(response.status_code, 401)
        self.assertIn('signature', response.json()['error'].lower())
        
        # Verify message was NOT saved
        self.assertEqual(DeviceMessage.objects.count(), 0)
        
        print("Test invalid signature rejected PASSED")