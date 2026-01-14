from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from datetime import datetime, timedelta
import pytz
from decimal import Decimal

from .models import Device, DeviceStatus, DeviceType
from .forms import DeviceRegistrationForm
from apps.core.models import UserProfile


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


class AddDeviceViewTest(TestCase):
    """Tests for the add_device view"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='participant1', password='testpass')
        self.user.profile.user_type = UserProfile.UserType.PARTICIPANT
        self.user.profile.save()
        self.device_type = DeviceType.objects.create(name="ESP32")
        self.url = reverse('participant:add_device')

    def test_add_device_requires_login(self):
        """Test add device page requires authentication"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.assertIn('/accounts/login/', response.url)

    def test_add_device_get_request(self):
        """Test GET request shows form"""
        self.client.login(username='participant1', password='testpass')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertIn('form', response.context)

    def test_add_device_post_valid(self):
        """Test POST request creates device"""
        self.client.login(username='participant1', password='testpass')
        form_data = {
            'name': 'New Sensor',
            'description': 'Test sensor',
            'device_type': self.device_type.id,
            'latitude': '54.687157',
            'longitude': '25.279652',
            'certificate_algorithm': 'ECDSA_P256'
        }
        response = self.client.post(self.url, data=form_data)
        self.assertEqual(response.status_code, 302)
        device = Device.objects.get(name='New Sensor')
        self.assertEqual(device.created_by, self.user)
        self.assertEqual(device.status, DeviceStatus.PENDING)


class RemoveDeviceViewTest(TestCase):
    """Tests for the remove_device view"""

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='owner', password='testpass')
        self.user.profile.user_type = UserProfile.UserType.PARTICIPANT
        self.user.profile.save()
        self.device = Device.objects.create(
            name='Test Device',
            latitude=Decimal('50.0'),
            longitude=Decimal('10.0'),
            created_by=self.user,
            status=DeviceStatus.PENDING
        )
        self.url = reverse('participant:remove_device', kwargs={'device_id': self.device.id})

    def test_remove_device_requires_post(self):
        """Test remove device only accepts POST"""
        self.client.login(username='owner', password='testpass')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, DeviceStatus.PENDING)

    def test_remove_device_success(self):
        """Test removing device sets status to REVOKED"""
        self.client.login(username='owner', password='testpass')
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 302)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, DeviceStatus.REVOKED)

    def test_remove_device_ownership_check(self):
        """Test user can only remove their own devices"""
        other_user = User.objects.create_user(username='other', password='testpass')
        other_user.profile.user_type = UserProfile.UserType.PARTICIPANT
        other_user.profile.save()
        self.client.login(username='other', password='testpass')
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 403)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, DeviceStatus.PENDING)


class CertificateGenerationViewTest(TestCase):
    """Tests for the generate_certificate view"""

    @classmethod
    def setUpTestData(cls):
        """Set up CA certificate for certificate generation tests"""
        from django.core.management import call_command
        from django.conf import settings
        import os

        if not os.path.exists(settings.CA_CERTIFICATE_PATH):
            call_command('create_ca')

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='certuser', password='testpass')
        self.user.profile.user_type = UserProfile.UserType.PARTICIPANT
        self.user.profile.save()
        self.device = Device.objects.create(
            name='Certificate Test Device',
            latitude=Decimal('50.0'),
            longitude=Decimal('10.0'),
            created_by=self.user,
            status=DeviceStatus.PENDING
        )
        self.url = reverse('participant:generate_certificate', kwargs={'device_id': self.device.id})

    def test_generate_certificate_requires_post(self):
        """Test generate certificate only accepts POST"""
        self.client.login(username='certuser', password='testpass')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
        self.device.refresh_from_db()
        self.assertIsNone(self.device.certificate_pem)

    def test_generate_certificate_success(self):
        """Test successful certificate generation"""
        self.client.login(username='certuser', password='testpass')
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 302)

        self.device.refresh_from_db()
        self.assertIsNotNone(self.device.certificate_pem)
        self.assertIsNotNone(self.device.private_key_pem)
        self.assertIsNotNone(self.device.certificate_serial)
        self.assertIsNotNone(self.device.certificate_expiry)
        self.assertIsNotNone(self.device.certificate_generated_at)
        self.assertEqual(self.device.status, DeviceStatus.PENDING)

    def test_generate_certificate_ownership_check(self):
        """Test user can only generate certificates for their own devices"""
        other_user = User.objects.create_user(username='otheruser', password='testpass')
        other_user.profile.user_type = UserProfile.UserType.PARTICIPANT
        other_user.profile.save()
        self.client.login(username='otheruser', password='testpass')

        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 403)
        self.device.refresh_from_db()
        self.assertIsNone(self.device.certificate_pem)

    def test_generate_certificate_revoked_device(self):
        """Test cannot generate certificate for revoked device"""
        self.device.status = DeviceStatus.REVOKED
        self.device.save()

        self.client.login(username='certuser', password='testpass')
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 302)

        self.device.refresh_from_db()
        self.assertIsNone(self.device.certificate_pem)

    def test_regenerate_certificate(self):
        """Test regenerating certificate replaces old one"""
        from django.utils import timezone

        self.client.login(username='certuser', password='testpass')

        # Generate first certificate
        self.client.post(self.url)
        self.device.refresh_from_db()
        first_serial = self.device.certificate_serial
        first_generated_at = self.device.certificate_generated_at

        # Wait a moment to ensure timestamp difference
        import time
        time.sleep(0.1)

        # Regenerate certificate
        self.client.post(self.url)
        self.device.refresh_from_db()

        self.assertIsNotNone(self.device.certificate_pem)
        self.assertNotEqual(self.device.certificate_serial, first_serial)
        self.assertGreater(self.device.certificate_generated_at, first_generated_at)


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
        self.assertEqual(response.status_code, 302)

    def test_download_certificate_expired_window(self):
        """Test download fails after 24-hour window"""
        from django.utils import timezone

        # Set certificate generation time to 25 hours ago
        self.device.certificate_generated_at = timezone.now() - timedelta(hours=25)
        self.device.save()

        self.client.login(username='downloaduser', password='testpass')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)


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
        self.assertEqual(response.status_code, 302)

    def test_download_private_key_expired_window(self):
        """Test download fails after 24-hour window"""
        from django.utils import timezone

        # Set certificate generation time to 25 hours ago
        self.device.certificate_generated_at = timezone.now() - timedelta(hours=25)
        self.device.save()

        self.client.login(username='keyuser', password='testpass')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
