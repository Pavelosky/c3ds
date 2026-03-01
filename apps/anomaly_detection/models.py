import uuid
from django.conf import settings
from django.db import models
from django.contrib.auth.models import User


class AnomalyType(models.TextChoices):
    DETECTION_RATE_SPIKE = 'DETECTION_RATE_SPIKE', 'Detection Rate Spike'
    SILENT_DEVICE = 'SILENT_DEVICE', 'Silent Device'
    AUTH_UNKNOWN_IP = 'AUTH_UNKNOWN_IP', 'Authentication from Unknown IP'
    AUTH_MALFORMED_MESSAGE = 'AUTH_MALFORMED_MESSAGE', 'Malformed Message Received'


class AnomalySeverity(models.TextChoices):
    LOW = 'LOW', 'Low'
    MEDIUM = 'MEDIUM', 'Medium'
    HIGH = 'HIGH', 'High'
    CRITICAL = 'CRITICAL', 'Critical'


class AnomalyFlag(models.Model):
    """
    Represents a detected anomaly in the device network.

    Flags are created automatically by the anomaly analysis system (scheduled via
    Celery Beat for periodic checks, or inline during certificate auth for real-time
    detection). An admin must explicitly resolve each flag.

    Design reference:
    - NIST SP 800-94: Guide to Intrusion Detection and Prevention Systems
    - Rule-based approach chosen over ML
    """

    # Which device the anomaly relates to (nullable for network-wide flags)
    device = models.ForeignKey(
        'device_management.Device',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='anomaly_flags',
        help_text="Device associated with this anomaly (null for network-wide flags)"
    )

    flag_type = models.CharField(
        max_length=40,
        choices=AnomalyType.choices,
        help_text="Type of anomaly detected"
    )

    severity = models.CharField(
        max_length=10,
        choices=AnomalySeverity.choices,
        default=AnomalySeverity.MEDIUM,
        help_text="Severity level of the anomaly"
    )

    # Human-readable explanation of why the flag was raised
    explanation = models.TextField(
        help_text="Plain-English description of why this flag was raised"
    )

    # Supporting data for investigation (e.g., message counts, IP addresses)
    detail = models.JSONField(
        default=dict,
        blank=True,
        help_text="Supporting data used to generate the flag (for admin investigation)"
    )

    raised_at = models.DateTimeField(
        auto_now_add=True,
        db_index=True
    )

    # Resolution tracking
    resolved_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="When the admin marked this flag as resolved"
    )

    resolved_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='resolved_flags',
        help_text="Admin user who resolved this flag"
    )

    class Meta:
        ordering = ['-raised_at']
        verbose_name = "Anomaly Flag"
        verbose_name_plural = "Anomaly Flags"

    def __str__(self):
        device_name = self.device.name if self.device else "Network"
        return f"[{self.severity}] {self.flag_type} — {device_name} ({self.raised_at:%Y-%m-%d %H:%M})"

    @property
    def is_resolved(self):
        return self.resolved_at is not None


class DeviceIPHistory(models.Model):
    """
    Tracks the set of IP addresses a device has successfully authenticated from.

    Used by (Authentication Anomaly Detection) to detect when a device
    communicates from an IP address it has never been seen at before.

    Per-device IP tracking was chosen over a general audit log to allow efficient
    lookups: checking if an IP is "known" for a device is a single indexed query.
    """
    device = models.ForeignKey(
        'device_management.Device',
        on_delete=models.CASCADE,
        related_name='ip_history',
        help_text="Device that communicated from this IP"
    )

    ip_address = models.GenericIPAddressField(
        help_text="IP address the device was seen from"
    )

    first_seen = models.DateTimeField(
        auto_now_add=True,
        help_text="First time this device was seen from this IP"
    )

    last_seen = models.DateTimeField(
        auto_now=True,
        help_text="Most recent time this device was seen from this IP"
    )

    class Meta:
        unique_together = [('device', 'ip_address')]
        verbose_name = "Device IP History"
        verbose_name_plural = "Device IP Histories"

    def __str__(self):
        return f"{self.device.name} @ {self.ip_address}"


# Incident Workspace 
class IncidentStatus(models.TextChoices):
    OPEN = 'OPEN', 'Open'
    INVESTIGATING = 'INVESTIGATING', 'Under Investigation'
    RESOLVED = 'RESOLVED', 'Resolved'
    ESCALATED = 'ESCALATED', 'Escalated'


class Incident(models.Model):
    """
    An investigation case grouping related anomaly flags and detection events.

    Provides admins with a structured place to track an ongoing incident from
    discovery through to resolution. Notes build a chronological investigation log.

    Design reference:
    - NIST SP 800-61 Rev 2: Computer Security Incident Handling Guide
    """
    title = models.CharField(
        max_length=255,
        help_text="Short descriptive title for the incident"
    )

    description = models.TextField(
        blank=True,
        help_text="Detailed description of what is being investigated"
    )

    severity = models.CharField(
        max_length=10,
        choices=AnomalySeverity.choices,
        default=AnomalySeverity.MEDIUM,
        help_text="Overall severity of the incident"
    )

    incident_status = models.CharField(
        max_length=15,
        choices=IncidentStatus.choices,
        default=IncidentStatus.OPEN,
        help_text="Current investigation status"
    )

    # Linked anomaly flags (M2M — flags can belong to multiple incidents)
    linked_flags = models.ManyToManyField(
        AnomalyFlag,
        blank=True,
        related_name='incidents',
        help_text="Anomaly flags associated with this incident"
    )

    # Linked detection events (M2M)
    linked_messages = models.ManyToManyField(
        'data_processing.DeviceMessage',
        blank=True,
        related_name='incidents',
        help_text="Detection events associated with this incident"
    )

    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_incidents',
        help_text="Admin who created this incident"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Incident"
        verbose_name_plural = "Incidents"

    def __str__(self):
        return f"[{self.incident_status}] {self.title}"


class IncidentNote(models.Model):
    """
    A single chronological note entry in an incident's investigation log.

    Notes are append-only — the interface provides no way to edit or delete them,
    building an immutable investigation trail as per NIST SP 800-61.
    """
    incident = models.ForeignKey(
        Incident,
        on_delete=models.CASCADE,
        related_name='notes',
        help_text="Incident this note belongs to"
    )

    content = models.TextField(
        help_text="Free-text investigation note"
    )

    author = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='incident_notes',
        help_text="Admin who wrote this note"
    )

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['created_at']
        verbose_name = "Incident Note"
        verbose_name_plural = "Incident Notes"

    def __str__(self):
        return f"Note on '{self.incident.title}' by {self.author} ({self.created_at:%Y-%m-%d %H:%M})"


# ============================================================================
# Command Queue
# ============================================================================

class CommandAction(models.TextChoices):
    SET_INTERVAL  = 'SET_INTERVAL',  'Change reporting interval'
    SET_THRESHOLD = 'SET_THRESHOLD', 'Change detection threshold'
    REBOOT        = 'REBOOT',        'Reboot device'


class CommandStatus(models.TextChoices):
    PENDING      = 'PENDING',      'Pending delivery'
    DELIVERED    = 'DELIVERED',    'Delivered to device'
    ACKNOWLEDGED = 'ACKNOWLEDGED', 'Acknowledged by device'
    EXPIRED      = 'EXPIRED',      'Expired undelivered'


class DeviceCommand(models.Model):
    """
    A command queued for delivery to an IoT device.

    Commands are delivered piggyback in the JSON response to the device's next
    incoming message (POST /api/v1/device/message/). The device parses the
    `commands` array, executes each command, and POSTs an acknowledgement to
    /api/v1/device/ack/.

    Supported actions:
    - SET_INTERVAL: change the heartbeat reporting interval (params: {"seconds": N})
    - SET_THRESHOLD: change the detection distance threshold (params: {"cm": N})
    - REBOOT: trigger a device reboot (params: {})

    Design reference:
    - Command pattern for remote device management
    - Polling delivery model chosen because embedded devices cannot receive
      push connections (ESP8266 acts as HTTP client only) and ar typically behind a firewall
    """
    id              = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    device          = models.ForeignKey(
        'device_management.Device',
        on_delete=models.CASCADE,
        related_name='commands',
        help_text="Target device for this command"
    )
    action          = models.CharField(
        max_length=32,
        choices=CommandAction.choices,
        help_text="Command action to execute on the device"
    )
    params          = models.JSONField(
        default=dict,
        blank=True,
        help_text="Action parameters (e.g. {'seconds': 60} for SET_INTERVAL)"
    )
    status          = models.CharField(
        max_length=16,
        choices=CommandStatus.choices,
        default=CommandStatus.PENDING,
        db_index=True,
        help_text="Current delivery status"
    )
    issued_by       = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='issued_commands',
        help_text="Admin user who dispatched this command (null = system/policy)"
    )
    created_at      = models.DateTimeField(auto_now_add=True, db_index=True)
    delivered_at    = models.DateTimeField(
        null=True, blank=True,
        help_text="When the command was included in a message response"
    )
    acknowledged_at = models.DateTimeField(
        null=True, blank=True,
        help_text="When the device confirmed execution"
    )
    expires_at      = models.DateTimeField(
        null=True, blank=True,
        help_text="Command is discarded undelivered after this time (null = never)"
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = "Device Command"
        verbose_name_plural = "Device Commands"

    def __str__(self):
        return f"{self.action} → {self.device.name} [{self.status}]"

    @property
    def is_expired(self):
        from django.utils import timezone
        return self.expires_at is not None and self.expires_at < timezone.now() and self.status == CommandStatus.PENDING
