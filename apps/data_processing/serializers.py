"""
Serializers for device messages.
File: apps/data_processing/serializers.py

Two serializers:
- DeviceMessageListSerializer: Minimal fields for list views
- DeviceMessageDetailSerializer: Full message data and metadata
"""

from rest_framework import serializers
from apps.data_processing.models import DeviceMessage


class DeviceMessageListSerializer(serializers.ModelSerializer):
    """
    Serializer for message list view.
    Minimal fields for performance in table views.
    
    Used by:
    - GET /api/v1/messages/
    - Included in DeviceDetailSerializer (recent messages)
    
    Example output:
    {
        "id": 123,
        "device": "e3bf7037-ca57-4928-9476-0e40e8b5d30d",
        "device_name": "ESP32-Sensor-01",
        "message_type": "heartbeat",
        "timestamp": "2024-01-14T10:30:00Z",
        "data_preview": "{\"status\": \"online\", \"battery\": 85}",
        "recieved_at": "2024-01-14T10:30:05Z"
    }
    """
    device_name = serializers.CharField(source='device.name', read_only=True)
    data_preview = serializers.SerializerMethodField()

    class Meta:
        model = DeviceMessage
        fields = [
            'id',
            'device',
            'device_name',
            'message_type',
            'timestamp',
            'data_preview',
            'recieved_at',
        ]

    def get_data_preview(self, obj):
        """
        Return first 100 characters of JSON data.
        Full data only shown in detail view.
        """
        import json
        data_str = json.dumps(obj.data)
        if len(data_str) > 100:
            return data_str[:100] + '...'
        return data_str


class DeviceMessageDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for message detail view.
    Includes full data payload and all metadata.

    Used by:
    - GET /api/v1/messages/{id}/

    Example output:
    {
        "id": 123,
        "device": "e3bf7037-ca57-4928-9476-0e40e8b5d30d",
        "device_name": "ESP32-Sensor-01",
        "device_status": "ACTIVE",
        "message_type": "heartbeat",
        "timestamp": "2024-01-14T10:30:00Z",
        "data": {
            "status": "online",
            "battery": 85,
            "temperature": 22.5,
            "location": {"lat": 54.687, "lng": 25.279}
        },
        "recieved_at": "2024-01-14T10:30:05Z",
        "certificate_serial": "1a2b3c4d5e6f"
    }

    Security note: ip_address field is intentionally excluded from serialization
    to prevent leaking device location/network information to frontend clients.
    IP addresses are still logged in the database for audit purposes.
    """
    device_name = serializers.CharField(source='device.name', read_only=True)
    device_status = serializers.CharField(source='device.status', read_only=True)

    class Meta:
        model = DeviceMessage
        fields = [
            'id',
            'device',
            'device_name',
            'device_status',
            'message_type',
            'timestamp',
            'data',
            'recieved_at',
            'certificate_serial',
        ]