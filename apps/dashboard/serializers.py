"""
Serializers for dashboard statistics.
File: apps/dashboard/serializers.py

This serializer aggregates data from multiple models,
so it's a plain Serializer (not ModelSerializer).
"""

from rest_framework import serializers


class DashboardStatsSerializer(serializers.Serializer):
    """
    Serializer for dashboard statistics.

    This is a plain Serializer (not ModelSerializer) because
    it aggregates data from multiple models (Device, DeviceMessage).

    Used by:
    - GET /api/v1/dashboard/stats/

    Example output:
    {
        "total_devices": 15,
        "active_devices": 12,
        "pending_devices": 2,
        "revoked_devices": 1,
        "total_messages": 1542,
        "messages_today": 142,
        "messages_this_week": 987,
        "devices_by_status": {
            "ACTIVE": 12,
            "PENDING": 2,
            "INACTIVE": 0,
            "REVOKED": 1,
            "EXPIRED": 0
        },
        "messages_by_day": [
            {"date": "2024-01-14", "count": 142},
            {"date": "2024-01-13", "count": 156},
            ...
        ]
    }
    """
    # Required stats
    total_devices = serializers.IntegerField()
    active_devices = serializers.IntegerField()
    pending_devices = serializers.IntegerField()
    revoked_devices = serializers.IntegerField()
    total_messages = serializers.IntegerField()
    messages_today = serializers.IntegerField()
    messages_this_week = serializers.IntegerField()

    # Optional detailed stats (can be added later)
    devices_by_status = serializers.DictField(
        child=serializers.IntegerField(),
        required=False,
        help_text="Device count grouped by status"
    )
    messages_by_day = serializers.ListField(
        child=serializers.DictField(),
        required=False,
        help_text="Message count for last 7 days"
    )