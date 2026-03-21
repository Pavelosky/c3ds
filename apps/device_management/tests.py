import tempfile
import os
from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User
from django.urls import reverse
from datetime import datetime, timedelta
import pytz
from decimal import Decimal

from rest_framework.test import APIClient
from rest_framework import status as drf_status

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.utils import timezone

from .models import Device, DeviceStatus, DeviceType, CertificateAlgorithm, DeviceAuditEntry
from .forms import DeviceRegistrationForm
from apps.core.models import UserProfile


# ---------------------------------------------------------------------------
# Test CA helper (used by new API-level tests)
# ---------------------------------------------------------------------------

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


class DeviceModelTest(TestCase):
    """Test suite for Device model"""
    
    @classmethod
    def setUpTestData(cls):
        """Set up data for the entire test class (runs once)"""
        from django.core.management import call_command
        from django.conf import settings
        import os
        
        if not os.path.exists(settings.CA_CERTIFICATE_PATH):
            call_command('create_ca')


    def setUp(self):
        """Set up test data that runs before each test"""
        self.user = User.objects.create_user(
            username='testadmin',
            password='testpass123'
        )
    
    def test_device_creation(self):
        """Test that a device is created with correct defaults"""
        device = Device.objects.create(
            name='Test Sensor 1',
            created_by=self.user
        )
        
        # Check device was created
        self.assertIsNotNone(device.id)
        
        # Check UUID format
        self.assertEqual(len(str(device.id)), 36)  # UUID string length
        
        # Check default status
        self.assertEqual(device.status, DeviceStatus.PENDING)
        
        # Check certificate fields are null by default
        self.assertIsNone(device.certificate_serial)
        self.assertIsNone(device.certificate_expiry)
        self.assertIsNone(device.certificate_pem)

    def test_device_str_representation(self):
        """Test the string representation of the device"""
        device = Device.objects.create(
            name='Test Sensor 2',
            status=DeviceStatus.ACTIVE,
            created_by=self.user
        )
        self.assertEqual(str(device), 'Test Sensor 2 (ACTIVE)')

    def test_device_status_transitions(self):
        """Test that device status can be updated correctly"""
        device = Device.objects.create(
            name='Test Sensor 3',
            created_by=self.user
        )
        
        # Initially PENDING
        self.assertEqual(device.status, DeviceStatus.PENDING)
        
        # Transition to ACTIVE
        device.status = DeviceStatus.ACTIVE
        device.save()
        device.refresh_from_db()
        self.assertEqual(device.status, DeviceStatus.ACTIVE)
        
        # Transition to REVOKED
        device.status = DeviceStatus.REVOKED
        device.save()
        device.refresh_from_db()
        self.assertEqual(device.status, DeviceStatus.REVOKED)

        # Transition to EXPIRED
        device.status = DeviceStatus.EXPIRED
        device.save()
        device.refresh_from_db()
        self.assertEqual(device.status, DeviceStatus.EXPIRED)

        # Transition to INACTIVE
        device.status = DeviceStatus.INACTIVE
        device.save()
        device.refresh_from_db()
        self.assertEqual(device.status, DeviceStatus.INACTIVE)

    def test_certificate_generation(self):
        """Test certificate generation creates valid cert"""
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from apps.device_management.utils import generate_device_certificate

        # Create a device
        device = Device.objects.create(
            name='Test Sensor 4',
            created_by=self.user
        )

        # Generate certificate
        cert_pem, key_pem, serial_hex, expiry_date = generate_device_certificate(device)

        # Update device with certificate info
        device.certificate_pem = cert_pem
        device.certificate_serial = serial_hex
        device.certificate_expiry = expiry_date
        device.save()
        device.refresh_from_db()

        # Verify certificate was generated
        self.assertIsNotNone(device.certificate_pem)
        self.assertIsNotNone(device.certificate_serial)
        self.assertIsNotNone(device.certificate_expiry)

        # Load certificate to verify it's valid
        cert = x509.load_pem_x509_certificate(
            device.certificate_pem.encode('utf-8'),
            default_backend()
        )

        # Check the certificate is valid and matches stored serial number
        self.assertEqual(format(cert.serial_number, 'x'), device.certificate_serial)

        now = datetime.utcnow().replace(tzinfo=pytz.UTC)
        cert_not_before = cert.not_valid_before.replace(tzinfo=pytz.UTC)
        cert_not_after = cert.not_valid_after.replace(tzinfo=pytz.UTC)

        self.assertLessEqual(cert_not_before, now)
        self.assertGreaterEqual(cert_not_after, now)


# ============= New Tests for Sprint 2: Device Management =============


class DeviceTypeModelTest(TestCase):
    """Tests for the DeviceType model"""

    def test_device_type_creation(self):
        """Test creating a device type"""
        device_type = DeviceType.objects.create(name="Raspberry Pi")
        self.assertEqual(device_type.name, "Raspberry Pi")
        self.assertEqual(str(device_type), "Raspberry Pi")

    def test_device_type_ordering(self):
        """Test device types are ordered alphabetically"""
        DeviceType.objects.create(name="ESP8266")
        DeviceType.objects.create(name="Arduino")
        DeviceType.objects.create(name="Raspberry Pi")

        types = list(DeviceType.objects.all())
        self.assertEqual(types[0].name, "Arduino")
        self.assertEqual(types[1].name, "ESP8266")
        self.assertEqual(types[2].name, "Raspberry Pi")


class DeviceWithLocationTest(TestCase):
    """Tests for Device model with new location fields"""

    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.device_type = DeviceType.objects.create(name="Raspberry Pi")

    def test_device_creation_with_location(self):
        """Test creating a device with location fields"""
        device = Device.objects.create(
            name="Test Sensor",
            description="Test description",
            device_type=self.device_type,
            latitude=Decimal('54.687157'),
            longitude=Decimal('25.279652'),
            created_by=self.user,
            status=DeviceStatus.PENDING
        )

        self.assertEqual(device.name, "Test Sensor")
        self.assertEqual(device.description, "Test description")
        self.assertEqual(device.device_type, self.device_type)
        self.assertEqual(device.latitude, Decimal('54.687157'))
        self.assertEqual(device.longitude, Decimal('25.279652'))
        self.assertEqual(device.status, DeviceStatus.PENDING)

    def test_device_without_optional_fields(self):
        """Test device can be created without optional fields"""
        device = Device.objects.create(
            name="Minimal Device",
            latitude=Decimal('50.0'),
            longitude=Decimal('10.0'),
            created_by=self.user
        )

        self.assertIsNone(device.description)
        self.assertIsNone(device.device_type)
        self.assertEqual(device.status, DeviceStatus.PENDING)


class DeviceRegistrationFormTest(TestCase):
    """Tests for the DeviceRegistrationForm"""

    def setUp(self):
        self.user = User.objects.create_user(username='formuser', password='testpass')
        self.device_type = DeviceType.objects.create(name="Raspberry Pi")

    def test_valid_form(self):
        """Test form with valid data"""
        form_data = {
            'name': 'Test Device',
            'description': 'Test description',
            'device_type': self.device_type.id,
            'latitude': '54.687157',
            'longitude': '25.279652',
            'certificate_algorithm': 'ECDSA_P256'
        }
        form = DeviceRegistrationForm(data=form_data, user=self.user)
        self.assertTrue(form.is_valid())

    def test_name_too_short(self):
        """Test form rejects name shorter than 3 characters"""
        form_data = {
            'name': 'AB',
            'latitude': '50.0',
            'longitude': '10.0'
        }
        form = DeviceRegistrationForm(data=form_data, user=self.user)
        self.assertFalse(form.is_valid())
        self.assertIn('name', form.errors)

    def test_name_too_long(self):
        """Test form rejects name longer than 50 characters"""
        form_data = {
            'name': 'A' * 51,
            'latitude': '50.0',
            'longitude': '10.0'
        }
        form = DeviceRegistrationForm(data=form_data, user=self.user)
        self.assertFalse(form.is_valid())
        self.assertIn('name', form.errors)

    def test_duplicate_device_name_same_user(self):
        """Test form rejects duplicate device name for same user"""
        Device.objects.create(
            name='Existing Device',
            latitude=Decimal('50.0'),
            longitude=Decimal('10.0'),
            created_by=self.user
        )

        form_data = {
            'name': 'Existing Device',
            'latitude': '60.0',
            'longitude': '20.0'
        }
        form = DeviceRegistrationForm(data=form_data, user=self.user)
        self.assertFalse(form.is_valid())
        self.assertIn('name', form.errors)

    def test_latitude_out_of_range(self):
        """Test form rejects invalid latitude"""
        form_data = {
            'name': 'Test Device',
            'latitude': '91.0',
            'longitude': '10.0'
        }
        form = DeviceRegistrationForm(data=form_data, user=self.user)
        self.assertFalse(form.is_valid())

    def test_longitude_out_of_range(self):
        """Test form rejects invalid longitude"""
        form_data = {
            'name': 'Test Device',
            'latitude': '50.0',
            'longitude': '181.0'
        }
        form = DeviceRegistrationForm(data=form_data, user=self.user)
        self.assertFalse(form.is_valid())


class DownloadCertificateViewTest(TestCase):
    """Tests for the download_certificate view"""

    @classmethod
    def setUpTestData(cls):
        """Set up CA certificate"""
        from django.core.management import call_command
        from django.conf import settings
        import os

        if not os.path.exists(settings.CA_CERTIFICATE_PATH):
            call_command('create_ca')

    def setUp(self):
        from django.utils import timezone
        from apps.device_management.utils import generate_device_certificate

        self.client = Client()
        self.user = User.objects.create_user(username='downloaduser', password='testpass')
        self.user.profile.user_type = UserProfile.UserType.PARTICIPANT
        self.user.profile.save()
        self.device = Device.objects.create(
            name='Download Test Device',
            latitude=Decimal('50.0'),
            longitude=Decimal('10.0'),
            created_by=self.user,
            status=DeviceStatus.PENDING
        )

        # Generate certificate
        cert_pem, key_pem, serial_hex, expiry_date = generate_device_certificate(self.device)
        self.device.certificate_pem = cert_pem
        self.device.private_key_pem = key_pem
        self.device.certificate_serial = serial_hex
        self.device.certificate_expiry = expiry_date
        self.device.certificate_generated_at = timezone.now()
        self.device.save()

        self.url = reverse('participant:download_certificate', kwargs={'device_id': self.device.id})

    def test_download_certificate_success(self):
        """Test successful certificate download"""
        self.client.login(username='downloaduser', password='testpass')
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/x-pem-file')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn('certificate.pem', response['Content-Disposition'])
        self.assertEqual(response.content.decode('utf-8'), self.device.certificate_pem)

    def test_download_certificate_ownership_check(self):
        """Test user can only download their own certificates"""
        other_user = User.objects.create_user(username='other', password='testpass')
        other_user.profile.user_type = UserProfile.UserType.PARTICIPANT
        other_user.profile.save()
        self.client.login(username='other', password='testpass')

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_download_certificate_no_cert(self):
        """Test download fails if no certificate exists"""
        device_no_cert = Device.objects.create(
            name='No Cert Device',
            latitude=Decimal('50.0'),
            longitude=Decimal('10.0'),
            created_by=self.user,
            status=DeviceStatus.PENDING
        )
        url = reverse('participant:download_certificate', kwargs={'device_id': device_no_cert.id})

        self.client.login(username='downloaduser', password='testpass')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)  # Not Found

    def test_download_certificate_expired_window(self):
        """Test download fails after 24-hour window"""
        from django.utils import timezone

        # Set certificate generation time to 25 hours ago
        self.device.certificate_generated_at = timezone.now() - timedelta(hours=25)
        self.device.save()

        self.client.login(username='downloaduser', password='testpass')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 410)  # Gone


class DownloadPrivateKeyViewTest(TestCase):
    """Tests for the download_private_key view"""

    @classmethod
    def setUpTestData(cls):
        """Set up CA certificate"""
        from django.core.management import call_command
        from django.conf import settings
        import os

        if not os.path.exists(settings.CA_CERTIFICATE_PATH):
            call_command('create_ca')

    def setUp(self):
        from django.utils import timezone
        from apps.device_management.utils import generate_device_certificate

        self.client = Client()
        self.user = User.objects.create_user(username='keyuser', password='testpass')
        self.user.profile.user_type = UserProfile.UserType.PARTICIPANT
        self.user.profile.save()
        self.device = Device.objects.create(
            name='Key Test Device',
            latitude=Decimal('50.0'),
            longitude=Decimal('10.0'),
            created_by=self.user,
            status=DeviceStatus.PENDING
        )

        # Generate certificate and key
        cert_pem, key_pem, serial_hex, expiry_date = generate_device_certificate(self.device)
        self.device.certificate_pem = cert_pem
        self.device.private_key_pem = key_pem
        self.device.certificate_serial = serial_hex
        self.device.certificate_expiry = expiry_date
        self.device.certificate_generated_at = timezone.now()
        self.device.save()

        self.url = reverse('participant:download_private_key', kwargs={'device_id': self.device.id})

    def test_download_private_key_success(self):
        """Test successful private key download"""
        self.client.login(username='keyuser', password='testpass')
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/x-pem-file')
        self.assertIn('attachment', response['Content-Disposition'])
        self.assertIn('private.key', response['Content-Disposition'])
        self.assertEqual(response.content.decode('utf-8'), self.device.private_key_pem)

    def test_download_private_key_ownership_check(self):
        """Test user can only download their own private keys"""
        other_user = User.objects.create_user(username='other', password='testpass')
        other_user.profile.user_type = UserProfile.UserType.PARTICIPANT
        other_user.profile.save()
        self.client.login(username='other', password='testpass')

        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 403)

    def test_download_private_key_no_key(self):
        """Test download fails if no private key exists"""
        device_no_key = Device.objects.create(
            name='No Key Device',
            latitude=Decimal('50.0'),
            longitude=Decimal('10.0'),
            created_by=self.user,
            status=DeviceStatus.PENDING
        )
        url = reverse('participant:download_private_key', kwargs={'device_id': device_no_key.id})

        self.client.login(username='keyuser', password='testpass')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)  # Not Found

    def test_download_private_key_expired_window(self):
        """Test download fails after 24-hour window"""
        from django.utils import timezone

        # Set certificate generation time to 25 hours ago
        self.device.certificate_generated_at = timezone.now() - timedelta(hours=25)
        self.device.save()

        self.client.login(username='keyuser', password='testpass')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 410)  # Gone


# ===========================================================================
# New API-level tests — ParticipantDeviceViewSet
# ===========================================================================

def _make_api_user(username, password='testpass123', is_staff=False):
    user = User.objects.create_user(username=username, password=password, is_staff=is_staff)
    return user


def _make_device(owner, name='TestDevice', dev_status=DeviceStatus.PENDING):
    dt, _ = DeviceType.objects.get_or_create(name='APITestType')
    return Device.objects.create(
        name=name,
        created_by=owner,
        status=dev_status,
        device_type=dt,
        certificate_algorithm=CertificateAlgorithm.ECDSA_P256,
    )


class ParticipantDeviceAPITests(TestCase):
    """Tests for ParticipantDeviceViewSet via the REST API."""

    def setUp(self):
        self.client = APIClient()
        self.owner = _make_api_user('apipariticipant')
        self.other = _make_api_user('apiother')
        self.client.force_login(self.owner)

    def test_unauthenticated_returns_403(self):
        self.client.logout()
        response = self.client.get('/api/v1/devices/participant/')
        self.assertEqual(response.status_code, drf_status.HTTP_403_FORBIDDEN)

    def test_list_returns_only_own_devices(self):
        _make_device(self.owner, name='Mine')
        _make_device(self.other, name='NotMine')
        response = self.client.get('/api/v1/devices/participant/')
        self.assertEqual(response.status_code, drf_status.HTTP_200_OK)
        names = [d['name'] for d in response.data]
        self.assertIn('Mine', names)
        self.assertNotIn('NotMine', names)

    def test_create_sets_owner_and_creates_audit(self):
        dt, _ = DeviceType.objects.get_or_create(name='CreateType')
        response = self.client.post('/api/v1/devices/participant/', {
            'name': 'CreateMe',
            'device_type': dt.pk,
            'certificate_algorithm': 'ECDSA_P256',
        }, format='json')
        self.assertEqual(response.status_code, drf_status.HTTP_201_CREATED)
        device = Device.objects.get(name='CreateMe')
        self.assertEqual(device.created_by, self.owner)
        self.assertTrue(
            DeviceAuditEntry.objects.filter(device=device, event_type='DEVICE_REGISTERED').exists()
        )

    def test_update_creates_device_updated_audit(self):
        device = _make_device(self.owner, name='UpdateMe')
        response = self.client.patch(
            f'/api/v1/devices/participant/{device.pk}/',
            {'name': 'UpdatedName'},
            format='json',
        )
        self.assertEqual(response.status_code, drf_status.HTTP_200_OK)
        self.assertTrue(
            DeviceAuditEntry.objects.filter(device=device, event_type='DEVICE_UPDATED').exists()
        )

    def test_delete_soft_revokes_and_creates_status_changed_audit(self):
        device = _make_device(self.owner, name='DeleteMe')
        response = self.client.delete(f'/api/v1/devices/participant/{device.pk}/')
        self.assertEqual(response.status_code, drf_status.HTTP_200_OK)
        device.refresh_from_db()
        self.assertEqual(device.status, DeviceStatus.REVOKED)
        self.assertTrue(Device.objects.filter(pk=device.pk).exists())
        self.assertTrue(
            DeviceAuditEntry.objects.filter(device=device, event_type='STATUS_CHANGED').exists()
        )

    def test_cannot_access_other_users_device(self):
        device = _make_device(self.other, name='OtherDevice')
        response = self.client.get(f'/api/v1/devices/participant/{device.pk}/')
        self.assertEqual(response.status_code, drf_status.HTTP_404_NOT_FOUND)

    def test_generate_certificate_revoked_returns_400(self):
        device = _make_device(self.owner, name='RevokedDevice', dev_status=DeviceStatus.REVOKED)
        ca_key, ca_cert = _generate_test_ca()
        with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as cf, \
             tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as kf:
            cf.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            kf.write(ca_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
            cert_path, key_path = cf.name, kf.name
        try:
            with override_settings(CA_CERTIFICATE_PATH=cert_path, CA_PRIVATE_KEY_PATH=key_path):
                response = self.client.post(
                    f'/api/v1/devices/participant/{device.pk}/generate-certificate/'
                )
            self.assertEqual(response.status_code, drf_status.HTTP_400_BAD_REQUEST)
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

    def test_generate_certificate_active_device_creates_cert_and_audit(self):
        device = _make_device(self.owner, name='ActiveCert', dev_status=DeviceStatus.ACTIVE)
        ca_key, ca_cert = _generate_test_ca()
        with tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as cf, \
             tempfile.NamedTemporaryFile(suffix='.pem', delete=False) as kf:
            cf.write(ca_cert.public_bytes(serialization.Encoding.PEM))
            kf.write(ca_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
            cert_path, key_path = cf.name, kf.name
        try:
            with override_settings(CA_CERTIFICATE_PATH=cert_path, CA_PRIVATE_KEY_PATH=key_path):
                response = self.client.post(
                    f'/api/v1/devices/participant/{device.pk}/generate-certificate/'
                )
            self.assertEqual(response.status_code, drf_status.HTTP_201_CREATED)
            device.refresh_from_db()
            self.assertIsNotNone(device.certificate_pem)
            self.assertTrue(
                DeviceAuditEntry.objects.filter(
                    device=device, event_type='CERTIFICATE_GENERATED').exists()
            )
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

    def test_download_certificate_no_cert_returns_404(self):
        device = _make_device(self.owner, name='NoCertDevice')
        response = self.client.get(
            f'/api/v1/devices/participant/{device.pk}/download-certificate/')
        self.assertEqual(response.status_code, drf_status.HTTP_404_NOT_FOUND)

    def test_download_certificate_expired_window_returns_410(self):
        device = _make_device(self.owner, name='ExpiredCert')
        device.certificate_pem = 'fake'
        device.private_key_pem = 'fake'
        device.certificate_generated_at = timezone.now() - timedelta(hours=25)
        device.save()
        response = self.client.get(
            f'/api/v1/devices/participant/{device.pk}/download-certificate/')
        self.assertEqual(response.status_code, drf_status.HTTP_410_GONE)

    def test_download_certificate_within_window_returns_file(self):
        device = _make_device(self.owner, name='ValidCert')
        device.certificate_pem = '---BEGIN CERTIFICATE---\nfake\n---END CERTIFICATE---'
        device.private_key_pem = 'fake'
        device.certificate_generated_at = timezone.now() - timedelta(hours=1)
        device.save()
        response = self.client.get(
            f'/api/v1/devices/participant/{device.pk}/download-certificate/')
        self.assertEqual(response.status_code, drf_status.HTTP_200_OK)
        self.assertIn('attachment', response.get('Content-Disposition', ''))

    def test_download_private_key_no_key_returns_404(self):
        device = _make_device(self.owner, name='NoKeyDevice')
        response = self.client.get(
            f'/api/v1/devices/participant/{device.pk}/download-private-key/')
        self.assertEqual(response.status_code, drf_status.HTTP_404_NOT_FOUND)

    def test_download_private_key_expired_window_returns_410(self):
        device = _make_device(self.owner, name='ExpiredKey')
        device.certificate_pem = 'fake'
        device.private_key_pem = 'fake'
        device.certificate_generated_at = timezone.now() - timedelta(hours=25)
        device.save()
        response = self.client.get(
            f'/api/v1/devices/participant/{device.pk}/download-private-key/')
        self.assertEqual(response.status_code, drf_status.HTTP_410_GONE)

    def test_download_private_key_within_window_returns_file(self):
        device = _make_device(self.owner, name='ValidKey')
        device.certificate_pem = 'fake'
        device.private_key_pem = '---BEGIN PRIVATE KEY---\nfake\n---END PRIVATE KEY---'
        device.certificate_generated_at = timezone.now() - timedelta(hours=1)
        device.save()
        response = self.client.get(
            f'/api/v1/devices/participant/{device.pk}/download-private-key/')
        self.assertEqual(response.status_code, drf_status.HTTP_200_OK)
        self.assertIn('attachment', response.get('Content-Disposition', ''))


class PublicDeviceAPITests(TestCase):
    """Tests for PublicDeviceViewSet."""

    def setUp(self):
        self.client = APIClient()
        self.user = _make_api_user('pubowner')

    def test_list_no_auth_required(self):
        response = self.client.get('/api/v1/devices/public/')
        self.assertEqual(response.status_code, drf_status.HTTP_200_OK)

    def test_filter_by_status_active(self):
        _make_device(self.user, name='ActiveDev', dev_status=DeviceStatus.ACTIVE)
        _make_device(self.user, name='PendingDev', dev_status=DeviceStatus.PENDING)
        response = self.client.get('/api/v1/devices/public/?status=ACTIVE')
        self.assertEqual(response.status_code, drf_status.HTTP_200_OK)
        for device in response.data:
            self.assertEqual(device['status'], 'ACTIVE')


class GenerateCertificateUtilityTests(TestCase):
    """Tests for generate_device_certificate() with a temporary test CA."""

    @classmethod
    def setUpTestData(cls):
        cls.ca_key, cls.ca_cert = _generate_test_ca()
        cls.user = User.objects.create_user(username='certutil', password='pass')

    def _write_temp_ca_files(self):
        cf = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
        kf = tempfile.NamedTemporaryFile(suffix='.pem', delete=False)
        cf.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))
        kf.write(self.ca_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()))
        cf.close()
        kf.close()
        return cf.name, kf.name

    def test_ecdsa_p256_returns_pem_strings(self):
        from apps.device_management.utils import generate_device_certificate
        cert_path, key_path = self._write_temp_ca_files()
        try:
            device = Device.objects.create(
                name='ECUtilDevice', created_by=self.user,
                certificate_algorithm=CertificateAlgorithm.ECDSA_P256,
            )
            with override_settings(CA_CERTIFICATE_PATH=cert_path, CA_PRIVATE_KEY_PATH=key_path):
                cert_pem, key_pem, serial_hex, expiry = generate_device_certificate(device)
            self.assertIn('BEGIN CERTIFICATE', cert_pem)
            self.assertIn('BEGIN', key_pem)
            self.assertIsInstance(serial_hex, str)
            self.assertIsNotNone(expiry)
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

    def test_rsa_2048_returns_pem_strings(self):
        from apps.device_management.utils import generate_device_certificate
        cert_path, key_path = self._write_temp_ca_files()
        try:
            device = Device.objects.create(
                name='RSAUtilDevice', created_by=self.user,
                certificate_algorithm=CertificateAlgorithm.RSA_2048,
            )
            with override_settings(CA_CERTIFICATE_PATH=cert_path, CA_PRIVATE_KEY_PATH=key_path):
                cert_pem, key_pem, serial_hex, expiry = generate_device_certificate(device)
            self.assertIn('BEGIN CERTIFICATE', cert_pem)
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)

    def test_unsupported_algorithm_raises_value_error(self):
        from apps.device_management.utils import generate_device_certificate
        cert_path, key_path = self._write_temp_ca_files()
        try:
            device = Device.objects.create(
                name='BadAlgoUtil', created_by=self.user,
                certificate_algorithm=CertificateAlgorithm.ECDSA_P256,
            )
            device.certificate_algorithm = 'UNSUPPORTED_ALGO'
            with override_settings(CA_CERTIFICATE_PATH=cert_path, CA_PRIVATE_KEY_PATH=key_path):
                with self.assertRaises(ValueError):
                    generate_device_certificate(device)
        finally:
            os.unlink(cert_path)
            os.unlink(key_path)
