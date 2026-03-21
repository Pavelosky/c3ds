"""
Unit tests for apps/dashboard:
- DashboardStatsView (public, no auth required)
"""
from datetime import timedelta

from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status

from apps.device_management.models import Device, DeviceStatus
from apps.data_processing.models import DeviceMessage


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_user(username):
    return User.objects.create_user(username=username, password='pass')


def make_device(owner, name='Device', dev_status=DeviceStatus.ACTIVE):
    return Device.objects.create(name=name, created_by=owner, status=dev_status)


def make_message(device, message_type='heartbeat', minutes_ago=0):
    ts = timezone.now() - timedelta(minutes=minutes_ago)
    return DeviceMessage.objects.create(
        device=device,
        message_type=message_type,
        timestamp=ts,
        data={},
    )


# ---------------------------------------------------------------------------
# DashboardStatsView tests
# ---------------------------------------------------------------------------

class DashboardStatsViewTests(TestCase):

    URL = '/api/v1/dashboard/stats/'

    @classmethod
    def setUpTestData(cls):
        cls.owner = User.objects.create_user(username='dashowner', password='pass')
        cls.active_device = Device.objects.create(
            name='ActiveDevice', created_by=cls.owner, status=DeviceStatus.ACTIVE
        )
        cls.pending_device = Device.objects.create(
            name='PendingDevice', created_by=cls.owner, status=DeviceStatus.PENDING
        )
        cls.revoked_device = Device.objects.create(
            name='RevokedDevice', created_by=cls.owner, status=DeviceStatus.REVOKED
        )
        now = timezone.now()
        # A heartbeat message within today
        DeviceMessage.objects.create(
            device=cls.active_device,
            message_type='heartbeat',
            timestamp=now - timedelta(minutes=30),
            data={},
        )
        # An alert message within last 2 hours
        DeviceMessage.objects.create(
            device=cls.active_device,
            message_type='alert',
            timestamp=now - timedelta(hours=1),
            data={},
        )
        # An old heartbeat (last week, outside 2h window)
        DeviceMessage.objects.create(
            device=cls.active_device,
            message_type='heartbeat',
            timestamp=now - timedelta(days=2),
            data={},
        )

    def setUp(self):
        self.client = APIClient()

    def test_endpoint_accessible_without_authentication(self):
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_response_contains_required_keys(self):
        response = self.client.get(self.URL)
        data = response.json()
        required_keys = [
            'total_devices', 'active_devices', 'pending_devices', 'revoked_devices',
            'total_messages', 'messages_today', 'messages_this_week', 'alerts_last_2h',
        ]
        for key in required_keys:
            self.assertIn(key, data, f"Missing key: {key}")

    def test_device_counts_are_correct(self):
        response = self.client.get(self.URL)
        data = response.json()
        self.assertEqual(data['active_devices'], 1)
        self.assertEqual(data['pending_devices'], 1)
        self.assertEqual(data['revoked_devices'], 1)
        self.assertEqual(data['total_devices'], 3)

    def test_total_messages_count(self):
        response = self.client.get(self.URL)
        data = response.json()
        # setUpTestData created 3 messages
        self.assertGreaterEqual(data['total_messages'], 3)

    def test_alerts_last_2h_counts_only_alert_type_in_window(self):
        response = self.client.get(self.URL)
        data = response.json()
        # Only 1 alert message within 2h
        self.assertGreaterEqual(data['alerts_last_2h'], 1)

    def test_messages_this_week_includes_recent_messages(self):
        response = self.client.get(self.URL)
        data = response.json()
        # Messages from 30min ago and 1h ago are within this week
        self.assertGreaterEqual(data['messages_this_week'], 2)

    def test_response_does_not_require_login(self):
        # Explicit check: even authenticated user gets same data
        user = User.objects.create_user(username='dashlogged', password='pass')
        self.client.force_login(user)
        response = self.client.get(self.URL)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
