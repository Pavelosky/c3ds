"""
Convenience function for writing DeviceAuditEntry records.

Centralising this keeps call sites concise and ensures consistent field
population. Import this wherever an auditable event occurs.
"""
from apps.device_management.models import DeviceAuditEntry


def log_audit_event(device, event_type, description, triggered_by=None, metadata=None):
    """
    Create a DeviceAuditEntry for a significant device event.

    Args:
        device:        Device instance
        event_type:    AuditEventType value (e.g. AuditEventType.STATUS_CHANGED)
        description:   Human-readable description of what happened
        triggered_by:  User instance, or None for system-triggered events
        metadata:      Optional dict of structured context (old/new values etc.)
    """
    DeviceAuditEntry.objects.create(
        device=device,
        event_type=event_type,
        description=description,
        triggered_by=triggered_by,
        metadata=metadata or {},
    )
