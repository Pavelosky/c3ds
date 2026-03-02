"""
Rule-based anomaly detection functions for C3DS.

Each function analyses a specific class of anomalous behaviour and creates
AnomalyFlag records where warranted. All rules are deterministic and threshold-
based — no ML is used.

Thresholds are defined as module-level constants so they can be overridden in
tests or easily tuned in the future.
"""
from django.utils import timezone
from django.db.models import Count, Avg, StdDev, Q
from datetime import timedelta

from .models import AnomalyFlag, AnomalyType, AnomalySeverity, DetectionPolicy, PolicyTriggerLog, PolicyConditionType, PolicyActionType


# ####### Thresholds ########### 
# A device is flagged if its message count in the last hour exceeds its
# 7-day hourly average by this factor.
SPIKE_MULTIPLIER = 3.0

# Minimum number of hourly observations needed before establishing a baseline.
# Devices with fewer observations than this are not flagged (insufficient history).
SPIKE_MIN_HISTORY_HOURS = 24

# US-04: Silent Device
# An ACTIVE device is flagged if it has not sent any message in this many minutes.
SILENCE_THRESHOLD_MINUTES = 60


# Deduplication helper 

def _flag_exists(flag_type, device=None):
    """
    Return True if an unresolved flag of this type already exists for this device.
    Prevents duplicate flags from accumulating across analysis cycles.
    """
    qs = AnomalyFlag.objects.filter(flag_type=flag_type, resolved_at__isnull=True)
    if device is not None:
        qs = qs.filter(device=device)
    return qs.exists()


# Detection Rate Spike 

def check_detection_rate_spike():
    """
    Flag devices whose message count in the last hour is SPIKE_MULTIPLIER times
    higher than their 7-day hourly average.

    Algorithm:
    1. For each ACTIVE device, count messages in the last hour.
    2. Count messages in the last 7 days, divide by 168 (hours in 7 days) to get
       the hourly average.
    3. If current_hour_count > average * SPIKE_MULTIPLIER, raise a flag.
    4. Devices with fewer than SPIKE_MIN_HISTORY_HOURS of data are skipped.

    Reference: NIST SP 800-94 §3.2.2 — Threshold-based anomaly detection.
    """
    from apps.device_management.models import Device, DeviceStatus
    from apps.data_processing.models import DeviceMessage

    now = timezone.now()
    hour_ago = now - timedelta(hours=1)
    seven_days_ago = now - timedelta(days=7)

    active_devices = Device.objects.filter(status=DeviceStatus.ACTIVE)

    for device in active_devices:
        # Skip if already flagged (unresolved)
        if _flag_exists(AnomalyType.DETECTION_RATE_SPIKE, device):
            continue

        # Count messages in the last hour
        current_count = DeviceMessage.objects.filter(
            device=device,
            recieved_at__gte=hour_ago
        ).count()

        if current_count == 0:
            continue

        # Count messages in the last 7 days for baseline
        history_count = DeviceMessage.objects.filter(
            device=device,
            recieved_at__gte=seven_days_ago
        ).count()

        # Need at least SPIKE_MIN_HISTORY_HOURS hours of messages to establish baseline.
        # Approximation: if history_count < SPIKE_MIN_HISTORY_HOURS, skip.
        if history_count < SPIKE_MIN_HISTORY_HOURS:
            continue

        # Hourly average over the 7-day window (168 hours)
        hourly_average = history_count / 168.0

        if hourly_average > 0 and current_count > hourly_average * SPIKE_MULTIPLIER:
            flag = AnomalyFlag.objects.create(
                device=device,
                flag_type=AnomalyType.DETECTION_RATE_SPIKE,
                severity=AnomalySeverity.HIGH,
                explanation=(
                    f"Device '{device.name}' sent {current_count} messages in the last hour, "
                    f"which is {current_count / hourly_average:.1f}x its 7-day hourly average "
                    f"of {hourly_average:.1f} messages/hour. This may indicate a malfunction "
                    f"or an attempt to flood the system with false detections."
                ),
                detail={
                    'current_hour_count': current_count,
                    'seven_day_hourly_average': round(hourly_average, 2),
                    'spike_ratio': round(current_count / hourly_average, 2),
                    'threshold_multiplier': SPIKE_MULTIPLIER,
                },
            )
            from apps.anomaly_detection.audit import log_audit_event
            from apps.device_management.models import AuditEventType
            log_audit_event(
                device=device,
                event_type=AuditEventType.ANOMALY_RAISED,
                description=f"Anomaly flag raised: Detection Rate Spike (flag #{flag.id}).",
                metadata={'flag_id': flag.id, 'flag_type': flag.flag_type},
            )


# Silent Device 

def check_silent_devices():
    """
    Flag ACTIVE devices that have not sent any message within SILENCE_THRESHOLD_MINUTES.

    A device is considered "silent" (not "offline") if it was previously active
    but has stopped communicating without being formally decommissioned. This is
    distinct from a device in INACTIVE or REVOKED status, which represents a
    deliberate operational decision.

    Reference: NIST SP 800-94 §3.2.1 — Missing expected events.
    """
    from apps.device_management.models import Device, DeviceStatus
    from apps.data_processing.models import DeviceMessage

    now = timezone.now()
    threshold = now - timedelta(minutes=SILENCE_THRESHOLD_MINUTES)

    active_devices = Device.objects.filter(status=DeviceStatus.ACTIVE)

    for device in active_devices:
        if _flag_exists(AnomalyType.SILENT_DEVICE, device):
            continue

        last_message = (
            DeviceMessage.objects.filter(device=device)
            .order_by('-recieved_at')
            .first()
        )

        if last_message is None:
            # Device has never sent a message — not flagged as "silent" since it
            # may still be in the process of first connection (PENDING covers this)
            continue

        if last_message.recieved_at < threshold:
            minutes_silent = int((now - last_message.recieved_at).total_seconds() / 60)

            flag = AnomalyFlag.objects.create(
                device=device,
                flag_type=AnomalyType.SILENT_DEVICE,
                severity=AnomalySeverity.MEDIUM,
                explanation=(
                    f"Device '{device.name}' has not communicated for {minutes_silent} minutes "
                    f"(last seen: {last_message.recieved_at.strftime('%Y-%m-%d %H:%M UTC')}). "
                    f"The device has not been formally decommissioned — this may indicate "
                    f"an unexpected communication failure."
                ),
                detail={
                    'last_seen': last_message.recieved_at.isoformat(),
                    'minutes_silent': minutes_silent,
                    'threshold_minutes': SILENCE_THRESHOLD_MINUTES,
                },
            )
            from apps.anomaly_detection.audit import log_audit_event
            from apps.device_management.models import AuditEventType
            log_audit_event(
                device=device,
                event_type=AuditEventType.ANOMALY_RAISED,
                description=f"Anomaly flag raised: Silent Device (flag #{flag.id}).",
                metadata={'flag_id': flag.id, 'flag_type': flag.flag_type},
            )


# ============================================================================
# Policy Engine
# ============================================================================

def _already_triggered_in_window(policy, device):
    """
    Return True if this policy already fired for this device within its cooldown window.

    CERT_EXPIRY_SOON and NO_MESSAGES_EVER use a fixed 24-hour cooldown because
    they have no meaningful window_minutes (the condition is time-since-event, not
    a rolling message-count window).
    """
    if policy.condition_type in (
        PolicyConditionType.CERT_EXPIRY_SOON,
        PolicyConditionType.NO_MESSAGES_EVER,
    ):
        cooldown = timedelta(hours=24)
    else:
        cooldown = timedelta(minutes=policy.window_minutes)

    return PolicyTriggerLog.objects.filter(
        policy=policy,
        device=device,
        triggered_at__gte=timezone.now() - cooldown,
    ).exists()


def _condition_met(policy, device, message):
    """
    Evaluate policy.condition_type against the device's current state.

    `message` is the freshly-saved DeviceMessage that triggered this evaluation,
    or None when called from the Celery periodic task.
    """
    from apps.data_processing.models import DeviceMessage

    now = timezone.now()
    ct = policy.condition_type

    if ct == PolicyConditionType.MESSAGE_RATE_HIGH:
        window_start = now - timedelta(minutes=policy.window_minutes)
        count = DeviceMessage.objects.filter(
            device=device, recieved_at__gte=window_start
        ).count()
        return count > policy.threshold_value

    if ct == PolicyConditionType.MESSAGE_RATE_LOW:
        window_start = now - timedelta(minutes=policy.window_minutes)
        count = DeviceMessage.objects.filter(
            device=device, recieved_at__gte=window_start
        ).count()
        return count < policy.threshold_value

    if ct == PolicyConditionType.CERT_EXPIRY_SOON:
        if not device.certificate_expiry:
            return False
        days_remaining = (device.certificate_expiry - now).days
        return days_remaining < policy.threshold_value

    if ct == PolicyConditionType.NO_MESSAGES_EVER:
        days_since_registration = (now - device.created_at).days
        if days_since_registration < policy.threshold_value:
            return False
        return not DeviceMessage.objects.filter(device=device).exists()

    if ct == PolicyConditionType.MESSAGE_TYPE_RATIO:
        window_start = now - timedelta(minutes=policy.window_minutes)
        total = DeviceMessage.objects.filter(
            device=device, recieved_at__gte=window_start
        ).count()
        if total == 0:
            return False
        detection_count = DeviceMessage.objects.filter(
            device=device, recieved_at__gte=window_start,
            message_type='detection',
        ).count()
        ratio = (detection_count / total) * 100
        return ratio > policy.threshold_value

    return False


def _execute_action(policy, device, message):
    """
    Execute policy.action_type and return a detail dict for the trigger log.
    """
    from apps.anomaly_detection.audit import log_audit_event
    from apps.device_management.models import AuditEventType, DeviceStatus

    detail = {
        'policy_id': str(policy.id),
        'condition_type': policy.condition_type,
        'threshold_value': policy.threshold_value,
        'action_type': policy.action_type,
    }

    flag = None

    if policy.action_type in (PolicyActionType.FLAG_ANOMALY, PolicyActionType.CREATE_INCIDENT):
        flag = AnomalyFlag.objects.create(
            device=device,
            flag_type=AnomalyType.POLICY_TRIGGERED,
            severity=policy.action_severity,
            explanation=(
                f"Policy '{policy.name}' triggered: condition {policy.condition_type} "
                f"met (threshold {policy.threshold_value}, window {policy.window_minutes} min). "
                f"Action: {policy.action_type}."
            ),
            detail={
                'policy_id': str(policy.id),
                'policy_name': policy.name,
                'condition_type': policy.condition_type,
                'threshold_value': policy.threshold_value,
                'window_minutes': policy.window_minutes,
            },
        )
        log_audit_event(
            device=device,
            event_type=AuditEventType.ANOMALY_RAISED,
            description=f"Policy '{policy.name}' raised anomaly flag #{flag.id}.",
            metadata={'flag_id': str(flag.id), 'policy_id': str(policy.id)},
        )
        detail['flag_id'] = str(flag.id)

    if policy.action_type == PolicyActionType.CREATE_INCIDENT:
        from .models import Incident
        incident = Incident.objects.create(
            title=f"Auto-incident: {policy.name}",
            description=(
                f"Automatically created by policy '{policy.name}' "
                f"(condition: {policy.condition_type}, threshold: {policy.threshold_value})."
            ),
            severity=policy.action_severity,
        )
        if flag:
            incident.linked_flags.add(flag)
        detail['incident_id'] = str(incident.id)

    if policy.action_type == PolicyActionType.QUEUE_COMMAND:
        from .models import DeviceCommand
        cmd = DeviceCommand.objects.create(
            device=device,
            action=policy.action_command,
            params=policy.action_command_params,
            issued_by=None,   # system-issued, not a named admin
        )
        detail['command_id'] = str(cmd.id)

    if policy.action_type == PolicyActionType.CHANGE_STATUS:
        if policy.action_device_status:
            old_status = device.status
            device.status = policy.action_device_status
            device.save(update_fields=['status'])
            log_audit_event(
                device=device,
                event_type=AuditEventType.STATUS_CHANGED,
                description=(
                    f"Policy '{policy.name}' changed device status "
                    f"from {old_status} to {policy.action_device_status}."
                ),
                metadata={
                    'old_status': old_status,
                    'new_status': policy.action_device_status,
                    'policy_id': str(policy.id),
                },
            )
            detail['old_status'] = old_status
            detail['new_status'] = policy.action_device_status

    return detail


def evaluate_policies_for_device(device, message=None):
    """
    Evaluate all active DetectionPolicy rules that apply to this device.

    Called after every valid inbound message (per-message conditions: RATE, RATIO)
    and from the Celery periodic task (covers CERT_EXPIRY_SOON, NO_MESSAGES_EVER,
    and devices that have gone quiet and no longer trigger per-message evaluation).

    Reference: NIST SP 800-94 §4 — Policy-based intrusion detection.
    """
    policies = DetectionPolicy.objects.filter(is_active=True).filter(
        Q(applies_to_device=device)
        | Q(applies_to_device__isnull=True, applies_to_type=device.device_type)
        | Q(applies_to_device__isnull=True, applies_to_type__isnull=True)
    ).select_related('applies_to_type', 'applies_to_device')

    for policy in policies:
        if _already_triggered_in_window(policy, device):
            continue
        if not _condition_met(policy, device, message):
            continue
        detail = _execute_action(policy, device, message)
        PolicyTriggerLog.objects.create(
            policy=policy,
            device=device,
            detail=detail,
        )
