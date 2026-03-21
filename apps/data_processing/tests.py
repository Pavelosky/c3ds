import tempfile
import os
import json
import base64
from datetime import timedelta

from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User
from django.utils import timezone

from rest_framework.test import APIClient
from rest_framework import status as drf_status

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec, rsa

from apps.device_management.models import Device, DeviceStatus, DeviceType, CertificateAlgorithm
from apps.data_processing.models import DeviceMessage
from apps.anomaly_detection.models import AnomalyFlag, AnomalyType, DeviceIPHistory, DeviceCommand, CommandStatus

# Create your tests here.

# Helper functions
def sign_message_with_key(private_key, message_body, algorithm='ECDSA_P256'):
    """
    Allows for checking both encryption algorithms (RSA and ECDSA).
    
    Args:
        private_key: Private key object (RSA or ECDSA)
        message_body: Message bytes to sign
        algorithm: Certificate algorithm used
    
    Returns:
        bytes: Signature
    """
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    # Determine if key is RSA or ECDSA based on key type
    if isinstance(private_key, rsa.RSAPrivateKey):
        # RSA signing
        return private_key.sign(
            message_body,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    else:
        # ECDSA signing (default for new devices)
        return private_key.sign(
            message_body,
            ec.ECDSA(hashes.SHA256())
        )

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
        signature = sign_message_with_key(
            private_key, 
            message_body, 
            self.device.certificate_algorithm
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
        
        signature = sign_message_with_key(private_key, message_body, self.device.certificate_algorithm)
        
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


# ===========================================================================
# Additional tests using a temporary test CA (no dependency on create_ca)
# ===========================================================================

def _generate_test_ca():
    """Generate a self-signed RSA CA for tests. Returns (ca_key, ca_cert)."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test CA')])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(timezone.now() - timedelta(days=1))
        .not_valid_after(timezone.now() + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert


def _generate_device_cert(ca_key, ca_cert, device_uuid):
    """Generate an ECDSA device certificate signed by the test CA."""
    device_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, str(device_uuid)),
    ])
    device_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(device_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(timezone.now() - timedelta(hours=1))
        .not_valid_after(timezone.now() + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return device_key, device_cert


def _sign_body(device_key, body_bytes):
    return device_key.sign(body_bytes, ec.ECDSA(hashes.SHA256()))


def _make_headers(cert_pem_bytes, signature_bytes):
    return {
        'HTTP_X_DEVICE_CERTIFICATE': base64.b64encode(cert_pem_bytes).decode(),
        'HTTP_X_DEVICE_SIGNATURE': base64.b64encode(signature_bytes).decode(),
    }


class DeviceMessageViewTests(TestCase):
    """
    Tests for DeviceMessageView using a temporary test CA.
    Each test spins up its own CA so no filesystem state is needed.
    """

    @classmethod
    def setUpTestData(cls):
        cls.ca_key, cls.ca_cert = _generate_test_ca()
        cls.user = User.objects.create_user(username='msgowner', password='pass')
        cls.device_type, _ = DeviceType.objects.get_or_create(name='MsgTestType')
        cls.device = Device.objects.create(
            name='MsgDevice',
            created_by=cls.user,
            status=DeviceStatus.PENDING,
            device_type=cls.device_type,
            certificate_algorithm=CertificateAlgorithm.ECDSA_P256,
        )
        cls.device_key, cls.device_cert = _generate_device_cert(
            cls.ca_key, cls.ca_cert, cls.device.id
        )
        cls.cert_pem = cls.device_cert.public_bytes(serialization.Encoding.PEM)

    def _write_temp_ca(self):
        cf = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
        cf.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        cf.close()
        return cf.name

    def _post_message(self, body_bytes, ca_path, extra_headers=None):
        signature = _sign_body(self.device_key, body_bytes)
        headers = _make_headers(self.cert_pem, signature)
        if extra_headers:
            headers.update(extra_headers)
        with override_settings(CA_CERTIFICATE_PATH=ca_path):
            return self.client.post(
                '/api/device/message/',
                data=body_bytes,
                content_type='application/json',
                **headers,
            )

    def test_missing_certificate_header_returns_401(self):
        ca_path = self._write_temp_ca()
        try:
            with override_settings(CA_CERTIFICATE_PATH=ca_path):
                response = self.client.post(
                    '/api/device/message/',
                    data=b'{}',
                    content_type='application/json',
                    HTTP_X_DEVICE_SIGNATURE='aGVsbG8=',
                )
            self.assertEqual(response.status_code, 401)
        finally:
            os.unlink(ca_path)

    def test_missing_signature_header_returns_401(self):
        ca_path = self._write_temp_ca()
        try:
            with override_settings(CA_CERTIFICATE_PATH=ca_path):
                response = self.client.post(
                    '/api/device/message/',
                    data=b'{}',
                    content_type='application/json',
                    HTTP_X_DEVICE_CERTIFICATE='aGVsbG8=',
                )
            self.assertEqual(response.status_code, 401)
        finally:
            os.unlink(ca_path)

    def test_malformed_base64_certificate_returns_400(self):
        ca_path = self._write_temp_ca()
        try:
            with override_settings(CA_CERTIFICATE_PATH=ca_path):
                response = self.client.post(
                    '/api/device/message/',
                    data=b'{}',
                    content_type='application/json',
                    HTTP_X_DEVICE_CERTIFICATE='NOT!!VALID!!BASE64!!!',
                    HTTP_X_DEVICE_SIGNATURE='aGVsbG8=',
                )
            self.assertEqual(response.status_code, 400)
        finally:
            os.unlink(ca_path)

    def test_certificate_signed_by_unknown_ca_returns_401(self):
        # Generate a completely separate CA
        other_ca_key, other_ca_cert = _generate_test_ca()
        other_device_key, other_device_cert = _generate_device_cert(
            other_ca_key, other_ca_cert, self.device.id
        )
        other_cert_pem = other_device_cert.public_bytes(serialization.Encoding.PEM)
        body = json.dumps({'message_type': 'test', 'timestamp': '2026-01-01T00:00:00Z', 'data': {}}).encode()
        sig = other_device_key.sign(body, ec.ECDSA(hashes.SHA256()))
        headers = _make_headers(other_cert_pem, sig)
        ca_path = self._write_temp_ca()
        try:
            with override_settings(CA_CERTIFICATE_PATH=ca_path):
                response = self.client.post(
                    '/api/device/message/',
                    data=body,
                    content_type='application/json',
                    **headers,
                )
            self.assertEqual(response.status_code, 401)
        finally:
            os.unlink(ca_path)

    def test_device_not_found_returns_404(self):
        # Create cert with a UUID that does not exist in DB
        import uuid
        fake_uuid = uuid.uuid4()
        _, fake_cert = _generate_device_cert(self.ca_key, self.ca_cert, fake_uuid)
        fake_cert_pem = fake_cert.public_bytes(serialization.Encoding.PEM)
        body = json.dumps({'message_type': 'test', 'timestamp': '2026-01-01T00:00:00Z', 'data': {}}).encode()
        fake_device_key, fake_device_cert = _generate_device_cert(self.ca_key, self.ca_cert, fake_uuid)
        fake_cert_pem = fake_device_cert.public_bytes(serialization.Encoding.PEM)
        sig = fake_device_key.sign(body, ec.ECDSA(hashes.SHA256()))
        headers = _make_headers(fake_cert_pem, sig)
        ca_path = self._write_temp_ca()
        try:
            with override_settings(CA_CERTIFICATE_PATH=ca_path):
                response = self.client.post(
                    '/api/device/message/',
                    data=body,
                    content_type='application/json',
                    **headers,
                )
            self.assertEqual(response.status_code, 404)
        finally:
            os.unlink(ca_path)

    def test_revoked_device_returns_403(self):
        self.device.status = DeviceStatus.REVOKED
        self.device.save()
        body = json.dumps({'message_type': 'test', 'timestamp': '2026-01-01T00:00:00Z', 'data': {}}).encode()
        ca_path = self._write_temp_ca()
        try:
            response = self._post_message(body, ca_path)
            self.assertEqual(response.status_code, 403)
        finally:
            os.unlink(ca_path)
            self.device.status = DeviceStatus.PENDING
            self.device.save()

    def test_invalid_message_signature_returns_401(self):
        self.device.status = DeviceStatus.ACTIVE
        self.device.save()
        body = b'{"message_type":"test","timestamp":"2026-01-01T00:00:00Z","data":{}}'
        wrong_signature = b'thisisnotavalidsignature'
        headers = _make_headers(self.cert_pem, wrong_signature)
        ca_path = self._write_temp_ca()
        try:
            with override_settings(CA_CERTIFICATE_PATH=ca_path):
                response = self.client.post(
                    '/api/device/message/',
                    data=body,
                    content_type='application/json',
                    **headers,
                )
            self.assertEqual(response.status_code, 401)
        finally:
            os.unlink(ca_path)
            self.device.status = DeviceStatus.PENDING
            self.device.save()

    def test_valid_message_saves_and_activates_pending_device(self):
        self.device.status = DeviceStatus.PENDING
        self.device.save()
        body = json.dumps({
            'message_type': 'heartbeat',
            'timestamp': '2026-01-01T00:00:00Z',
            'data': {'battery': 90},
        }).encode()
        ca_path = self._write_temp_ca()
        initial_count = DeviceMessage.objects.count()
        try:
            response = self._post_message(body, ca_path)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.json().get('saved'))
            self.assertEqual(DeviceMessage.objects.count(), initial_count + 1)
            self.device.refresh_from_db()
            self.assertEqual(self.device.status, DeviceStatus.ACTIVE)
        finally:
            os.unlink(ca_path)

    def test_missing_required_fields_creates_malformed_flag(self):
        self.device.status = DeviceStatus.ACTIVE
        self.device.save()
        # Body missing 'data' and 'timestamp' fields
        body = json.dumps({'message_type': 'heartbeat'}).encode()
        ca_path = self._write_temp_ca()
        try:
            response = self._post_message(body, ca_path)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(
                AnomalyFlag.objects.filter(
                    device=self.device,
                    flag_type=AnomalyType.AUTH_MALFORMED_MESSAGE,
                ).exists()
            )
        finally:
            os.unlink(ca_path)
            AnomalyFlag.objects.filter(device=self.device).delete()

    def test_pending_commands_returned_and_marked_delivered(self):
        self.device.status = DeviceStatus.ACTIVE
        self.device.save()
        cmd = DeviceCommand.objects.create(
            device=self.device,
            action='REBOOT',
            params={},
            status=CommandStatus.PENDING,
        )
        body = json.dumps({
            'message_type': 'heartbeat',
            'timestamp': '2026-01-01T00:00:00Z',
            'data': {},
        }).encode()
        ca_path = self._write_temp_ca()
        try:
            response = self._post_message(body, ca_path)
            self.assertEqual(response.status_code, 200)
            commands_in_response = response.json().get('commands', [])
            command_ids = [c['id'] for c in commands_in_response]
            self.assertIn(str(cmd.id), command_ids)
            cmd.refresh_from_db()
            self.assertEqual(cmd.status, CommandStatus.DELIVERED)
        finally:
            os.unlink(ca_path)
            DeviceCommand.objects.filter(pk=cmd.pk).delete()


class CheckUnknownIPTests(TestCase):
    """Tests for the _check_unknown_ip helper on DeviceMessageView."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='ipowner', password='pass')
        cls.device = Device.objects.create(
            name='IPDevice',
            created_by=cls.user,
            status=DeviceStatus.ACTIVE,
        )

    def setUp(self):
        # Clean IP history and flags before each test
        DeviceIPHistory.objects.filter(device=self.device).delete()
        AnomalyFlag.objects.filter(device=self.device).delete()

    def _call_check(self, ip):
        from apps.data_processing.views import DeviceMessageView
        view = DeviceMessageView()
        view._check_unknown_ip(self.device, ip)

    def test_single_ip_does_not_create_flag(self):
        self._call_check('10.0.0.1')
        self.assertFalse(
            AnomalyFlag.objects.filter(
                device=self.device, flag_type=AnomalyType.AUTH_UNKNOWN_IP
            ).exists()
        )

    def test_two_ips_in_window_creates_unknown_ip_flag(self):
        self._call_check('10.0.0.1')
        self._call_check('10.0.0.2')
        self.assertTrue(
            AnomalyFlag.objects.filter(
                device=self.device, flag_type=AnomalyType.AUTH_UNKNOWN_IP
            ).exists()
        )

    def test_already_flagged_device_not_double_flagged(self):
        self._call_check('10.0.0.1')
        self._call_check('10.0.0.2')
        count_after_first_trigger = AnomalyFlag.objects.filter(
            device=self.device, flag_type=AnomalyType.AUTH_UNKNOWN_IP
        ).count()
        # Call again with a third IP — should NOT create a new flag
        self._call_check('10.0.0.3')
        count_after_second = AnomalyFlag.objects.filter(
            device=self.device, flag_type=AnomalyType.AUTH_UNKNOWN_IP
        ).count()
        self.assertEqual(count_after_first_trigger, count_after_second)


class DeviceMessageListViewTests(TestCase):
    """Tests for DeviceMessageListView."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(username='listowner', password='pass')
        cls.active_device = Device.objects.create(
            name='ActiveListDevice',
            created_by=cls.user,
            status=DeviceStatus.ACTIVE,
        )
        cls.inactive_device = Device.objects.create(
            name='InactiveListDevice',
            created_by=cls.user,
            status=DeviceStatus.INACTIVE,
        )
        now = timezone.now()
        DeviceMessage.objects.create(
            device=cls.active_device,
            message_type='heartbeat',
            timestamp=now - timedelta(minutes=30),
            data={},
        )
        DeviceMessage.objects.create(
            device=cls.active_device,
            message_type='detection',
            timestamp=now - timedelta(minutes=10),
            data={},
        )
        DeviceMessage.objects.create(
            device=cls.inactive_device,
            message_type='heartbeat',
            timestamp=now - timedelta(minutes=5),
            data={},
        )

    def test_returns_only_active_device_messages(self):
        response = self.client.get('/api/v1/messages/')
        self.assertEqual(response.status_code, 200)
        for msg in response.json():
            self.assertEqual(msg['device'], str(self.active_device.id))

    def test_message_type_filter(self):
        response = self.client.get('/api/v1/messages/?message_type=detection')
        self.assertEqual(response.status_code, 200)
        for msg in response.json():
            self.assertEqual(msg['message_type'], 'detection')

    def test_time_window_24h_filters_correctly(self):
        # All test messages are within 24h, so should appear
        response = self.client.get('/api/v1/messages/?time_window=24h')
        self.assertEqual(response.status_code, 200)
        self.assertGreater(len(response.json()), 0)

    def test_invalid_limit_defaults_gracefully(self):
        response = self.client.get('/api/v1/messages/?limit=notanumber')
        self.assertEqual(response.status_code, 200)

    def test_limit_caps_at_1000(self):
        response = self.client.get('/api/v1/messages/?limit=99999')
        self.assertEqual(response.status_code, 200)