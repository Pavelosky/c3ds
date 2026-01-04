from django.test import TestCase
from django.contrib.auth.models import User
from datetime import datetime, timedelta
import pytz

from .models import Device, DeviceStatus


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
