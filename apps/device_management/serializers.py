"""
Serializers for device management.
File: apps/device_management/serializers.py

Three serializers for different use cases:
- DeviceListSerializer: Fast, minimal fields for list views
- DeviceDetailSerializer: Full info for single device page
- DeviceRegistrationSerializer: Only fields user can set when registering
"""

from rest_framework import serializers
from apps.device_management.models import Device, DeviceType
from apps.core.serializers import UserSerializer


class DeviceListSerializer(serializers.ModelSerializer):
    """
    Serializer for device list view.
    Minimal fields for performance in tables/cards.
    
    Used by:
    - GET /api/v1/devices/public/
    - GET /api/v1/devices/participant/
    
    Example output:
    {
        "id": "e3bf7037-ca57-4928-9476-0e40e8b5d30d",
        "name": "ESP32-Sensor-01",
        "device_type": "ESP32",
        "status": "ACTIVE",
        "status_display": "Active",
        "created_at": "2024-01-14T10:00:00Z",
        "updated_at": "2024-01-14T10:00:00Z",
        "message_count": 42
    }
    """
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    message_count = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = [
            'id',
            'name',
            'device_type',
            'latitude',
            'longitude',
            'status',
            'status_display',
            'created_at',
            'updated_at',
            'message_count',
        ]

    def get_message_count(self, obj):
        """Return count of messages from this device."""
        return obj.messages.count()


class DeviceDetailSerializer(serializers.ModelSerializer):
    """
    Serializer for device detail view.
    Includes all fields, relationships, and recent activity.
    
    Used by:
    - GET /api/v1/devices/public/{id}/
    - GET /api/v1/devices/participant/{id}/
    
    Example output:
    {
        "id": "e3bf7037-ca57-4928-9476-0e40e8b5d30d",
        "name": "ESP32-Sensor-01",
        "device_type": "ESP32",
        "location": "Vilnius, Lithuania",
        "status": "ACTIVE",
        "status_display": "Active",
        "created_by": {
            "id": 1,
            "username": "participant1",
            "profile": {"user_type": "PARTICIPANT"},
            "date_joined": "2024-01-01T10:00:00Z"
        },
        "created_at": "2024-01-14T10:00:00Z",
        "updated_at": "2024-01-14T10:00:00Z",
        "message_count": 42,
        "recent_messages": [...]
    }
    """
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    created_by = UserSerializer(read_only=True)
    message_count = serializers.SerializerMethodField()
    recent_messages = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = [
            'id',
            'name',
            'device_type',
            'latitude',
            'longitude',
            'status',
            'status_display',
            'created_by',
            'created_at',
            'updated_at',
            'message_count',
            'recent_messages',
        ]

    def get_message_count(self, obj):
        """Return count of messages from this device."""
        return obj.messages.count()

    def get_recent_messages(self, obj):
        """
        Return 5 most recent messages from this device.
        Uses DeviceMessageListSerializer to avoid circular import.
        """
        from apps.data_processing.serializers import DeviceMessageListSerializer
        recent = obj.messages.order_by('-timestamp')[:5]
        return DeviceMessageListSerializer(recent, many=True).data


class DeviceRegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for creating new devices.
    Used when participants register new devices.

    Used by:
    - POST /api/v1/devices/participant/

    Only includes fields that participants can set.
    Status is automatically set to PENDING.
    created_by is set in the view from request.user.

    Example input:
    {
        "name": "ESP32-Sensor-01",
        "device_type": "ESP32",
        "location": "Vilnius, Lithuania",
        "certificate_algorithm": "ECDSA_P256"
    }
    """
    # Accept device_type as string (device type name), will be converted to ID
    device_type = serializers.CharField(write_only=True, required=False, allow_blank=True, allow_null=True)

    class Meta:
        model = Device
        fields = [
            'name',
            'description',
            'device_type',
            'latitude',
            'longitude',
            'certificate_algorithm',
        ]

    def validate_name(self, value):
        """
        Validate device name.
        Check that name is not already taken by this user.
        """
        user = self.context['request'].user

        # Check if user already has a device with this name
        if Device.objects.filter(name=value, created_by=user).exists():
            raise serializers.ValidationError(
                "You already have a device with this name."
            )

        return value

    def validate_device_type(self, value):
        """
        Convert device type name to DeviceType object.
        Creates DeviceType if it doesn't exist.
        """
        if not value:
            return None

        # Try to get existing DeviceType by name
        device_type, created = DeviceType.objects.get_or_create(name=value)
        return device_type

    def create(self, validated_data):
        """
        Create device with PENDING status.
        created_by will be set in view from request.user.
        """
        # device_type is already a DeviceType object from validate_device_type
        validated_data['status'] = 'PENDING'
        return super().create(validated_data)