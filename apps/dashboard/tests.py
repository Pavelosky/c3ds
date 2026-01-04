from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from apps.device_management.models import Device, DeviceStatus
from apps.data_processing.models import DeviceMessage
from datetime import datetime
import pytz

# Create your tests here.

class DashboardViewTest(TestCase):
    """Test suite for Dashboard view"""
    
    def setUp(self):
        """Set up test data for each test"""
        self.client = Client()
        self.url = '/'  # Dashboard is at root
        
        # Create user and device
        self.user = User.objects.create_user(username='testadmin', password='testpass')
        self.device = Device.objects.create(
            name='Dashboard Test Device',
            status=DeviceStatus.ACTIVE,
            created_by=self.user
        )
        
        # Create test messages
        self.message1 = DeviceMessage.objects.create(
            device=self.device,
            message_type='heartbeat',
            timestamp=datetime(2024, 12, 13, 10, 0, 0, tzinfo=pytz.UTC),
            data={'status': 'online'},
            ip_address='192.168.1.100'
        )
        
        self.message2 = DeviceMessage.objects.create(
            device=self.device,
            message_type='detection',
            timestamp=datetime(2024, 12, 13, 11, 0, 0, tzinfo=pytz.UTC),
            data={'drone_detected': True},
            ip_address='192.168.1.100'
        )

    def test_dashboard_loads_successfully(self):
        """Test that dashboard page loads and displays messages"""
        response = self.client.get(self.url)
        
        # Check response
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'dashboard/index.html')
        
        # Check context contains messages
        self.assertIn('messages', response.context)
        self.assertIn('devices', response.context)
        
        # Check both messages are in context
        self.assertEqual(response.context['messages'].count(), 2)
        
        print("Test dashboard loads successfully PASSED")
    
    def test_dashboard_filter_by_device(self):
        """Test filtering messages by device"""
        # Create second device with message
        device2 = Device.objects.create(
            name='Second Device',
            status=DeviceStatus.ACTIVE,
            created_by=self.user
        )
        
        DeviceMessage.objects.create(
            device=device2,
            message_type='alert',
            timestamp=datetime(2024, 12, 13, 12, 0, 0, tzinfo=pytz.UTC),
            data={'alert': 'test'},
            ip_address='192.168.1.101'
        )
        
        # Filter by first device
        response = self.client.get(self.url, {'device': str(self.device.id)})
        
        self.assertEqual(response.status_code, 200)
        
        # Should only show first device's messages (2 messages)
        self.assertEqual(response.context['messages'].count(), 2)
        
        # All messages should be from first device
        for message in response.context['messages']:
            self.assertEqual(message.device, self.device)
        
        print("Test dashboard filter by device PASSED")

    def test_dashboard_filter_by_status(self):
        """Test filtering messages by device status"""
        # Create inactive device with message
        inactive_device = Device.objects.create(
            name='Inactive Device',
            status=DeviceStatus.INACTIVE,
            created_by=self.user
        )
        
        DeviceMessage.objects.create(
            device=inactive_device,
            message_type='offline',
            timestamp=datetime(2024, 12, 13, 13, 0, 0, tzinfo=pytz.UTC),
            data={'status': 'offline'},
            ip_address='192.168.1.102'
        )
        
        # Filter by ACTIVE status
        response = self.client.get(self.url, {'status': 'ACTIVE'})
        
        self.assertEqual(response.status_code, 200)
        
        # Should only show ACTIVE device's messages
        self.assertEqual(response.context['messages'].count(), 2)
        
        # All messages should be from ACTIVE devices
        for message in response.context['messages']:
            self.assertEqual(message.device.status, DeviceStatus.ACTIVE)
        
        print("Test dashboard filter by status PASSED")

    def test_dashboard_filter_by_date(self):
        """Test filtering messages by date"""
        # Filter by specific date
        response = self.client.get(self.url, {'date': '2024-12-13'})
        
        self.assertEqual(response.status_code, 200)
        
        # Should show both messages from that date
        self.assertEqual(response.context['messages'].count(), 2)
        
        # Filter by different date (no messages)
        response = self.client.get(self.url, {'date': '2024-12-14'})
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['messages'].count(), 0)
        
        print("Test dashboard filter by date PASSED")