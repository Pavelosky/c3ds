"""
Unit tests for apps/anomaly_detection:
- _flag_exists() deduplication helper
- check_detection_rate_spike()
- check_silent_devices()
- _condition_met() for all policy condition types
- _already_triggered_in_window()
- _execute_action() for all policy action types
- evaluate_policies_for_device()
- _haversine_km() utility
- Admin API views (AnomalyFlagViewSet, AnomalySummaryView, IncidentViewSet,
  DeviceCommandView, AdminDeviceSetStatusView, EventCorrelationView,
  DetectionPolicyDetailView)
"""
from datetime import timedelta

from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status

from apps.device_management.models import Device, DeviceStatus, DeviceType, DeviceAuditEntry
from apps.data_processing.models import DeviceMessage
from apps.anomaly_detection.models import (
    AnomalyFlag, AnomalyType, AnomalySeverity,
    Incident, IncidentStatus, IncidentNote,
    DeviceCommand, CommandStatus,
    DetectionPolicy, PolicyConditionType, PolicyActionType, PolicyTriggerLog,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_user(username, password='testpass123', is_staff=False):
    user = User.objects.create_user(username=username, password=password, is_staff=is_staff)
    return user


def make_device(owner, name='TestDevice', dev_status=DeviceStatus.ACTIVE):
    dt, _ = DeviceType.objects.get_or_create(name='AnomalyTestType')
    return Device.objects.create(name=name, created_by=owner, status=dev_status, device_type=dt)


def make_message(device, message_type='heartbeat', minutes_ago=0):
    ts = timezone.now() - timedelta(minutes=minutes_ago)
    return DeviceMessage.objects.create(
        device=device,
        message_type=message_type,
        timestamp=ts,
        data={},
    )


def make_flag(device, flag_type=AnomalyType.SILENT_DEVICE, resolved=False):
    flag = AnomalyFlag.objects.create(
        device=device,
        flag_type=flag_type,
        severity=AnomalySeverity.MEDIUM,
        explanation='test flag',
    )
    if resolved:
        flag.resolved_at = timezone.now()
        flag.save()
    return flag


def make_policy(condition_type, action_type, threshold=5.0, window=60,
                action_severity=AnomalySeverity.MEDIUM, device=None, device_type=None):
    return DetectionPolicy.objects.create(
        name=f'Policy-{condition_type}-{action_type}',
        condition_type=condition_type,
        action_type=action_type,
        threshold_value=threshold,
        window_minutes=window,
        action_severity=action_severity,
        is_active=True,
        applies_to_device=device,
        applies_to_type=device_type,
    )


# ===========================================================================
# _flag_exists() tests
# ===========================================================================

class FlagExistsTests(TestCase):

    def setUp(self):
        self.user = make_user('flagowner')
        self.device = make_device(self.user)

    def test_returns_true_for_unresolved_flag(self):
        from apps.anomaly_detection.detection import _flag_exists
        make_flag(self.device, flag_type=AnomalyType.SILENT_DEVICE, resolved=False)
        self.assertTrue(_flag_exists(AnomalyType.SILENT_DEVICE, self.device))

    def test_returns_false_for_resolved_flag(self):
        from apps.anomaly_detection.detection import _flag_exists
        make_flag(self.device, flag_type=AnomalyType.SILENT_DEVICE, resolved=True)
        self.assertFalse(_flag_exists(AnomalyType.SILENT_DEVICE, self.device))

    def test_returns_false_when_no_flag(self):
        from apps.anomaly_detection.detection import _flag_exists
        self.assertFalse(_flag_exists(AnomalyType.SILENT_DEVICE, self.device))

    def test_device_filter_works(self):
        from apps.anomaly_detection.detection import _flag_exists
        other_device = make_device(self.user, name='OtherDevice')
        make_flag(other_device, flag_type=AnomalyType.SILENT_DEVICE)
        # Flag exists for other_device, not for self.device
        self.assertFalse(_flag_exists(AnomalyType.SILENT_DEVICE, self.device))


# ===========================================================================
# check_detection_rate_spike() tests
# ===========================================================================

class DetectionRateSpikeTests(TestCase):

    def setUp(self):
        self.user = make_user('spikeowner')
        self.device = make_device(self.user, dev_status=DeviceStatus.ACTIVE)

    def tearDown(self):
        AnomalyFlag.objects.filter(device=self.device).delete()
        DeviceMessage.objects.filter(device=self.device).delete()

    def test_device_with_insufficient_history_not_flagged(self):
        from apps.anomaly_detection.detection import check_detection_rate_spike, SPIKE_MIN_HISTORY_HOURS
        # Create fewer messages than SPIKE_MIN_HISTORY_HOURS (< 24 msgs in 7 days)
        for i in range(SPIKE_MIN_HISTORY_HOURS - 1):
            make_message(self.device, minutes_ago=i * 60)
        check_detection_rate_spike()
        self.assertFalse(
            AnomalyFlag.objects.filter(
                device=self.device, flag_type=AnomalyType.DETECTION_RATE_SPIKE
            ).exists()
        )

    def test_device_with_zero_messages_last_hour_not_flagged(self):
        from apps.anomaly_detection.detection import check_detection_rate_spike, SPIKE_MIN_HISTORY_HOURS
        # Enough history but none in the last hour
        for i in range(SPIKE_MIN_HISTORY_HOURS + 10):
            make_message(self.device, minutes_ago=i * 60 + 120)  # all older than 2h
        check_detection_rate_spike()
        self.assertFalse(
            AnomalyFlag.objects.filter(
                device=self.device, flag_type=AnomalyType.DETECTION_RATE_SPIKE
            ).exists()
        )

    def test_spike_creates_flag_with_high_severity(self):
        from apps.anomaly_detection.detection import check_detection_rate_spike, SPIKE_MIN_HISTORY_HOURS, SPIKE_MULTIPLIER
        # Create enough history (SPIKE_MIN_HISTORY_HOURS messages spread over 7 days)
        for i in range(SPIKE_MIN_HISTORY_HOURS):
            make_message(self.device, minutes_ago=i * 60 + 120)
        # Create a spike: way more messages in the last hour
        # history_count / 168 is the hourly average; need current > avg * SPIKE_MULTIPLIER
        hourly_avg = SPIKE_MIN_HISTORY_HOURS / 168.0
        spike_count = int(hourly_avg * SPIKE_MULTIPLIER) + 5
        for _ in range(spike_count):
            make_message(self.device, minutes_ago=10)
        check_detection_rate_spike()
        flag = AnomalyFlag.objects.filter(
            device=self.device, flag_type=AnomalyType.DETECTION_RATE_SPIKE
        ).first()
        self.assertIsNotNone(flag)
        self.assertEqual(flag.severity, AnomalySeverity.HIGH)

    def test_already_flagged_device_not_double_flagged(self):
        from apps.anomaly_detection.detection import check_detection_rate_spike, SPIKE_MIN_HISTORY_HOURS, SPIKE_MULTIPLIER
        make_flag(self.device, flag_type=AnomalyType.DETECTION_RATE_SPIKE)
        for i in range(SPIKE_MIN_HISTORY_HOURS):
            make_message(self.device, minutes_ago=i * 60 + 120)
        hourly_avg = SPIKE_MIN_HISTORY_HOURS / 168.0
        spike_count = int(hourly_avg * SPIKE_MULTIPLIER) + 5
        for _ in range(spike_count):
            make_message(self.device, minutes_ago=10)
        check_detection_rate_spike()
        # Should still be exactly 1 flag
        self.assertEqual(
            AnomalyFlag.objects.filter(
                device=self.device, flag_type=AnomalyType.DETECTION_RATE_SPIKE
            ).count(), 1
        )


# ===========================================================================
# check_silent_devices() tests
# ===========================================================================

class SilentDeviceTests(TestCase):

    def setUp(self):
        self.user = make_user('silentowner')
        self.device = make_device(self.user, dev_status=DeviceStatus.ACTIVE)

    def tearDown(self):
        AnomalyFlag.objects.filter(device=self.device).delete()
        DeviceMessage.objects.filter(device=self.device).delete()

    def test_device_never_messaged_not_flagged(self):
        from apps.anomaly_detection.detection import check_silent_devices
        check_silent_devices()
        self.assertFalse(
            AnomalyFlag.objects.filter(
                device=self.device, flag_type=AnomalyType.SILENT_DEVICE
            ).exists()
        )

    def test_device_with_recent_message_not_flagged(self):
        from apps.anomaly_detection.detection import check_silent_devices
        make_message(self.device, minutes_ago=30)  # within 60-minute threshold
        check_silent_devices()
        self.assertFalse(
            AnomalyFlag.objects.filter(
                device=self.device, flag_type=AnomalyType.SILENT_DEVICE
            ).exists()
        )

    def test_device_silent_over_threshold_flagged_with_medium_severity(self):
        from apps.anomaly_detection.detection import check_silent_devices, SILENCE_THRESHOLD_MINUTES
        make_message(self.device, minutes_ago=SILENCE_THRESHOLD_MINUTES + 10)
        check_silent_devices()
        flag = AnomalyFlag.objects.filter(
            device=self.device, flag_type=AnomalyType.SILENT_DEVICE
        ).first()
        self.assertIsNotNone(flag)
        self.assertEqual(flag.severity, AnomalySeverity.MEDIUM)

    def test_already_flagged_silent_device_not_double_flagged(self):
        from apps.anomaly_detection.detection import check_silent_devices, SILENCE_THRESHOLD_MINUTES
        make_flag(self.device, flag_type=AnomalyType.SILENT_DEVICE)
        make_message(self.device, minutes_ago=SILENCE_THRESHOLD_MINUTES + 10)
        check_silent_devices()
        self.assertEqual(
            AnomalyFlag.objects.filter(
                device=self.device, flag_type=AnomalyType.SILENT_DEVICE
            ).count(), 1
        )


# ===========================================================================
# Policy engine tests
# ===========================================================================

class ConditionMetTests(TestCase):

    def setUp(self):
        self.user = make_user('condowner')
        self.device = make_device(self.user, dev_status=DeviceStatus.ACTIVE)

    def tearDown(self):
        DeviceMessage.objects.filter(device=self.device).delete()

    def test_message_rate_high_true_when_above_threshold(self):
        from apps.anomaly_detection.detection import _condition_met
        for _ in range(10):
            make_message(self.device, minutes_ago=5)
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY, threshold=5.0, window=60)
        self.assertTrue(_condition_met(policy, self.device, None))

    def test_message_rate_high_false_when_below_threshold(self):
        from apps.anomaly_detection.detection import _condition_met
        for _ in range(2):
            make_message(self.device, minutes_ago=5)
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY, threshold=10.0, window=60)
        self.assertFalse(_condition_met(policy, self.device, None))

    def test_message_rate_low_true_when_below_threshold(self):
        from apps.anomaly_detection.detection import _condition_met
        # Only 1 message in window, threshold = 5
        make_message(self.device, minutes_ago=5)
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_LOW, PolicyActionType.FLAG_ANOMALY, threshold=5.0, window=60)
        self.assertTrue(_condition_met(policy, self.device, None))

    def test_message_rate_low_false_when_above_threshold(self):
        from apps.anomaly_detection.detection import _condition_met
        for _ in range(10):
            make_message(self.device, minutes_ago=5)
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_LOW, PolicyActionType.FLAG_ANOMALY, threshold=5.0, window=60)
        self.assertFalse(_condition_met(policy, self.device, None))

    def test_cert_expiry_soon_true_when_cert_expiring(self):
        from apps.anomaly_detection.detection import _condition_met
        self.device.certificate_expiry = timezone.now() + timedelta(days=5)
        self.device.save()
        policy = make_policy(PolicyConditionType.CERT_EXPIRY_SOON, PolicyActionType.FLAG_ANOMALY, threshold=10.0)
        self.assertTrue(_condition_met(policy, self.device, None))

    def test_cert_expiry_soon_false_when_cert_not_expiring(self):
        from apps.anomaly_detection.detection import _condition_met
        self.device.certificate_expiry = timezone.now() + timedelta(days=100)
        self.device.save()
        policy = make_policy(PolicyConditionType.CERT_EXPIRY_SOON, PolicyActionType.FLAG_ANOMALY, threshold=10.0)
        self.assertFalse(_condition_met(policy, self.device, None))

    def test_cert_expiry_soon_false_when_no_cert(self):
        from apps.anomaly_detection.detection import _condition_met
        self.device.certificate_expiry = None
        self.device.save()
        policy = make_policy(PolicyConditionType.CERT_EXPIRY_SOON, PolicyActionType.FLAG_ANOMALY, threshold=10.0)
        self.assertFalse(_condition_met(policy, self.device, None))

    def test_no_messages_ever_true_when_old_device_with_no_messages(self):
        from apps.anomaly_detection.detection import _condition_met
        # Simulate device registered 10+ days ago with 0 messages
        self.device.created_at = timezone.now() - timedelta(days=15)
        Device.objects.filter(pk=self.device.pk).update(created_at=self.device.created_at)
        policy = make_policy(PolicyConditionType.NO_MESSAGES_EVER, PolicyActionType.FLAG_ANOMALY, threshold=7.0)
        self.assertTrue(_condition_met(policy, self.device, None))

    def test_no_messages_ever_false_when_device_has_messages(self):
        from apps.anomaly_detection.detection import _condition_met
        make_message(self.device, minutes_ago=100)
        Device.objects.filter(pk=self.device.pk).update(
            created_at=timezone.now() - timedelta(days=15)
        )
        policy = make_policy(PolicyConditionType.NO_MESSAGES_EVER, PolicyActionType.FLAG_ANOMALY, threshold=7.0)
        self.assertFalse(_condition_met(policy, self.device, None))

    def test_message_type_ratio_true_when_ratio_above_threshold(self):
        from apps.anomaly_detection.detection import _condition_met
        # 8 detection, 2 other = 80% ratio
        for _ in range(8):
            make_message(self.device, message_type='detection', minutes_ago=5)
        for _ in range(2):
            make_message(self.device, message_type='heartbeat', minutes_ago=5)
        policy = make_policy(PolicyConditionType.MESSAGE_TYPE_RATIO, PolicyActionType.FLAG_ANOMALY, threshold=70.0, window=60)
        self.assertTrue(_condition_met(policy, self.device, None))

    def test_message_type_ratio_false_when_no_messages(self):
        from apps.anomaly_detection.detection import _condition_met
        policy = make_policy(PolicyConditionType.MESSAGE_TYPE_RATIO, PolicyActionType.FLAG_ANOMALY, threshold=70.0, window=60)
        self.assertFalse(_condition_met(policy, self.device, None))


class AlreadyTriggeredInWindowTests(TestCase):

    def setUp(self):
        self.user = make_user('triggerowner')
        self.device = make_device(self.user)

    def test_returns_true_within_cooldown(self):
        from apps.anomaly_detection.detection import _already_triggered_in_window
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY, window=60)
        PolicyTriggerLog.objects.create(policy=policy, device=self.device, detail={})
        self.assertTrue(_already_triggered_in_window(policy, self.device))

    def test_returns_false_outside_cooldown(self):
        from apps.anomaly_detection.detection import _already_triggered_in_window
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY, window=60)
        # Log entry from 2 hours ago — outside the 60-min window
        log = PolicyTriggerLog.objects.create(policy=policy, device=self.device, detail={})
        PolicyTriggerLog.objects.filter(pk=log.pk).update(
            triggered_at=timezone.now() - timedelta(hours=2)
        )
        self.assertFalse(_already_triggered_in_window(policy, self.device))

    def test_cert_expiry_uses_24h_cooldown(self):
        from apps.anomaly_detection.detection import _already_triggered_in_window
        policy = make_policy(PolicyConditionType.CERT_EXPIRY_SOON, PolicyActionType.FLAG_ANOMALY, window=60)
        # Log entry from 12h ago — within 24h cooldown
        log = PolicyTriggerLog.objects.create(policy=policy, device=self.device, detail={})
        PolicyTriggerLog.objects.filter(pk=log.pk).update(
            triggered_at=timezone.now() - timedelta(hours=12)
        )
        self.assertTrue(_already_triggered_in_window(policy, self.device))


class ExecuteActionTests(TestCase):

    def setUp(self):
        self.user = make_user('execowner')
        self.device = make_device(self.user, dev_status=DeviceStatus.ACTIVE)

    def tearDown(self):
        AnomalyFlag.objects.filter(device=self.device).delete()
        DeviceCommand.objects.filter(device=self.device).delete()

    def test_flag_anomaly_creates_flag(self):
        from apps.anomaly_detection.detection import _execute_action
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY)
        _execute_action(policy, self.device, None)
        self.assertTrue(
            AnomalyFlag.objects.filter(
                device=self.device, flag_type=AnomalyType.POLICY_TRIGGERED
            ).exists()
        )

    def test_create_incident_creates_incident_and_flag(self):
        from apps.anomaly_detection.detection import _execute_action
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.CREATE_INCIDENT)
        _execute_action(policy, self.device, None)
        self.assertTrue(Incident.objects.filter(title__startswith='Auto-incident').exists())
        self.assertTrue(
            AnomalyFlag.objects.filter(device=self.device, flag_type=AnomalyType.POLICY_TRIGGERED).exists()
        )

    def test_queue_command_creates_device_command(self):
        from apps.anomaly_detection.detection import _execute_action
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.QUEUE_COMMAND)
        policy.action_command = 'REBOOT'
        policy.action_command_params = {}
        policy.save()
        _execute_action(policy, self.device, None)
        self.assertTrue(DeviceCommand.objects.filter(device=self.device, action='REBOOT').exists())

    def test_change_status_updates_device(self):
        from apps.anomaly_detection.detection import _execute_action
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.CHANGE_STATUS)
        policy.action_device_status = DeviceStatus.INACTIVE
        policy.save()
        _execute_action(policy, self.device, None)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, DeviceStatus.INACTIVE)


class EvaluatePoliciesTests(TestCase):

    def setUp(self):
        self.user = make_user('evalowner')
        self.device = make_device(self.user, dev_status=DeviceStatus.ACTIVE)

    def tearDown(self):
        AnomalyFlag.objects.filter(device=self.device).delete()
        PolicyTriggerLog.objects.all().delete()
        DetectionPolicy.objects.all().delete()
        DeviceMessage.objects.filter(device=self.device).delete()

    def test_inactive_policy_skipped(self):
        from apps.anomaly_detection.detection import evaluate_policies_for_device
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY, threshold=1.0)
        policy.is_active = False
        policy.save()
        for _ in range(10):
            make_message(self.device, minutes_ago=5)
        evaluate_policies_for_device(self.device, None)
        self.assertFalse(AnomalyFlag.objects.filter(device=self.device).exists())

    def test_cooldown_prevents_repeat_trigger(self):
        from apps.anomaly_detection.detection import evaluate_policies_for_device
        for _ in range(10):
            make_message(self.device, minutes_ago=5)
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY, threshold=1.0, window=60)
        # Pre-log a trigger within the window
        PolicyTriggerLog.objects.create(policy=policy, device=self.device, detail={})
        evaluate_policies_for_device(self.device, None)
        self.assertFalse(AnomalyFlag.objects.filter(device=self.device).exists())

    def test_global_policy_applies_to_all_devices(self):
        from apps.anomaly_detection.detection import evaluate_policies_for_device
        for _ in range(10):
            make_message(self.device, minutes_ago=5)
        policy = make_policy(
            PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY,
            threshold=1.0, window=60, device=None, device_type=None
        )
        evaluate_policies_for_device(self.device, None)
        self.assertTrue(AnomalyFlag.objects.filter(device=self.device).exists())

    def test_device_specific_policy_applies_to_target_device(self):
        from apps.anomaly_detection.detection import evaluate_policies_for_device
        for _ in range(10):
            make_message(self.device, minutes_ago=5)
        policy = make_policy(
            PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY,
            threshold=1.0, window=60, device=self.device
        )
        evaluate_policies_for_device(self.device, None)
        self.assertTrue(AnomalyFlag.objects.filter(device=self.device).exists())


# ===========================================================================
# _haversine_km() tests
# ===========================================================================

class HaversineTests(TestCase):

    def test_same_point_returns_zero(self):
        from apps.anomaly_detection.api_views import _haversine_km
        self.assertAlmostEqual(_haversine_km(54.687, 25.279, 54.687, 25.279), 0.0, places=3)

    def test_known_distance_vilnius_to_kaunas(self):
        from apps.anomaly_detection.api_views import _haversine_km
        # Vilnius: 54.6872, 25.2797 | Kaunas: 54.8985, 23.9036
        dist = _haversine_km(54.6872, 25.2797, 54.8985, 23.9036)
        self.assertGreater(dist, 95)
        self.assertLess(dist, 105)

    def test_antipodal_points_close_to_earth_diameter(self):
        from apps.anomaly_detection.api_views import _haversine_km
        dist = _haversine_km(0, 0, 0, 180)
        self.assertGreater(dist, 20000)


# ===========================================================================
# Admin API view tests
# ===========================================================================

class AnomalyFlagAdminTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.admin = make_user('flagadmin', is_staff=True)
        self.regular = make_user('flagnormal')
        self.device_owner = make_user('flagdevowner')
        self.device = make_device(self.device_owner)

    def test_non_admin_returns_403(self):
        self.client.force_login(self.regular)
        response = self.client.get('/api/v1/admin/anomaly-flags/')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_can_list_flags(self):
        make_flag(self.device, flag_type=AnomalyType.SILENT_DEVICE)
        self.client.force_login(self.admin)
        response = self.client.get('/api/v1/admin/anomaly-flags/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data), 1)

    def test_resolved_filter_false_excludes_resolved(self):
        make_flag(self.device, flag_type=AnomalyType.SILENT_DEVICE, resolved=True)
        make_flag(self.device, flag_type=AnomalyType.AUTH_UNKNOWN_IP, resolved=False)
        self.client.force_login(self.admin)
        response = self.client.get('/api/v1/admin/anomaly-flags/?resolved=false')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        for flag in response.data:
            self.assertIsNone(flag.get('resolved_at'))

    def test_resolve_action_marks_flag_resolved(self):
        flag = make_flag(self.device, flag_type=AnomalyType.SILENT_DEVICE)
        self.client.force_login(self.admin)
        response = self.client.post(f'/api/v1/admin/anomaly-flags/{flag.pk}/resolve/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        flag.refresh_from_db()
        self.assertIsNotNone(flag.resolved_at)
        self.assertEqual(flag.resolved_by, self.admin)

    def test_resolve_already_resolved_flag_returns_400(self):
        flag = make_flag(self.device, flag_type=AnomalyType.SILENT_DEVICE, resolved=True)
        self.client.force_login(self.admin)
        response = self.client.post(f'/api/v1/admin/anomaly-flags/{flag.pk}/resolve/')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_resolve_creates_audit_entry(self):
        flag = make_flag(self.device, flag_type=AnomalyType.SILENT_DEVICE)
        self.client.force_login(self.admin)
        self.client.post(f'/api/v1/admin/anomaly-flags/{flag.pk}/resolve/')
        self.assertTrue(
            DeviceAuditEntry.objects.filter(
                device=self.device, event_type='ANOMALY_RESOLVED'
            ).exists()
        )


class AnomalySummaryViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.admin = make_user('summaryadmin', is_staff=True)
        self.device_owner = make_user('summaryowner')
        self.device = make_device(self.device_owner)

    def test_admin_gets_summary(self):
        make_flag(self.device, flag_type=AnomalyType.SILENT_DEVICE)
        self.client.force_login(self.admin)
        response = self.client.get('/api/v1/admin/anomaly-flags/summary/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsInstance(response.data, list)

    def test_non_admin_gets_403(self):
        regular = make_user('summaryregular')
        self.client.force_login(regular)
        response = self.client.get('/api/v1/admin/anomaly-flags/summary/')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class IncidentViewSetTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.admin = make_user('incidentadmin', is_staff=True)
        self.regular = make_user('incidentnormal')

    def test_non_admin_cannot_create_incident(self):
        self.client.force_login(self.regular)
        response = self.client.post('/api/v1/admin/incidents/', {
            'title': 'Test Incident',
            'severity': 'MEDIUM',
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_can_create_incident(self):
        self.client.force_login(self.admin)
        response = self.client.post('/api/v1/admin/incidents/', {
            'title': 'Admin Test Incident',
            'description': 'Test',
            'severity': 'MEDIUM',
        }, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(Incident.objects.filter(title='Admin Test Incident').exists())

    def test_add_note_creates_note(self):
        incident = Incident.objects.create(
            title='Note Test', severity='MEDIUM', created_by=self.admin
        )
        self.client.force_login(self.admin)
        response = self.client.post(
            f'/api/v1/admin/incidents/{incident.pk}/notes/',
            {'content': 'Investigation note'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(IncidentNote.objects.filter(incident=incident).exists())


class DeviceCommandViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.admin = make_user('cmdadmin', is_staff=True)
        self.device_owner = make_user('cmdowner')
        self.device = make_device(self.device_owner)

    def test_invalid_action_returns_400(self):
        self.client.force_login(self.admin)
        response = self.client.post(
            f'/api/v1/admin/devices/{self.device.pk}/commands/',
            {'action': 'INVALID_ACTION', 'params': {}},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_valid_action_creates_command_and_audit(self):
        self.client.force_login(self.admin)
        response = self.client.post(
            f'/api/v1/admin/devices/{self.device.pk}/commands/',
            {'action': 'REBOOT', 'params': {}},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertTrue(DeviceCommand.objects.filter(device=self.device, action='REBOOT').exists())
        self.assertTrue(
            DeviceAuditEntry.objects.filter(
                device=self.device, event_type='COMMAND_DISPATCHED'
            ).exists()
        )

    def test_device_not_found_returns_404(self):
        import uuid
        self.client.force_login(self.admin)
        response = self.client.post(
            f'/api/v1/admin/devices/{uuid.uuid4()}/commands/',
            {'action': 'REBOOT', 'params': {}},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class AdminDeviceSetStatusTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.admin = make_user('statusadmin', is_staff=True)
        self.device_owner = make_user('statusowner')
        self.device = make_device(self.device_owner, dev_status=DeviceStatus.ACTIVE)

    def test_invalid_status_returns_400(self):
        self.client.force_login(self.admin)
        response = self.client.post(
            f'/api/v1/admin/devices/{self.device.pk}/set-status/',
            {'status': 'NONSENSE'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_valid_status_change_updates_device_and_audit(self):
        self.client.force_login(self.admin)
        response = self.client.post(
            f'/api/v1/admin/devices/{self.device.pk}/set-status/',
            {'status': 'INACTIVE'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.device.refresh_from_db()
        self.assertEqual(self.device.status, DeviceStatus.INACTIVE)
        self.assertTrue(
            DeviceAuditEntry.objects.filter(
                device=self.device, event_type='STATUS_CHANGED'
            ).exists()
        )

    def test_device_not_found_returns_404(self):
        import uuid
        self.client.force_login(self.admin)
        response = self.client.post(
            f'/api/v1/admin/devices/{uuid.uuid4()}/set-status/',
            {'status': 'INACTIVE'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class DetectionPolicyDetailViewTests(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.admin = make_user('policyadmin', is_staff=True)

    def test_delete_blocked_when_policy_fired_recently(self):
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY)
        device_owner = make_user('policydelowner')
        device = make_device(device_owner)
        PolicyTriggerLog.objects.create(policy=policy, device=device, detail={})
        self.client.force_login(self.admin)
        response = self.client.delete(f'/api/v1/admin/policies/{policy.pk}/')
        self.assertEqual(response.status_code, status.HTTP_409_CONFLICT)

    def test_delete_with_confirm_succeeds(self):
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY)
        device_owner = make_user('policydelowner2')
        device = make_device(device_owner)
        PolicyTriggerLog.objects.create(policy=policy, device=device, detail={})
        self.client.force_login(self.admin)
        response = self.client.delete(f'/api/v1/admin/policies/{policy.pk}/?confirm=1')
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_delete_policy_not_found_returns_404(self):
        import uuid
        self.client.force_login(self.admin)
        response = self.client.delete(f'/api/v1/admin/policies/{uuid.uuid4()}/')
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_patch_policy_updates_fields(self):
        policy = make_policy(PolicyConditionType.MESSAGE_RATE_HIGH, PolicyActionType.FLAG_ANOMALY)
        self.client.force_login(self.admin)
        response = self.client.patch(
            f'/api/v1/admin/policies/{policy.pk}/',
            {'is_active': False},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        policy.refresh_from_db()
        self.assertFalse(policy.is_active)
