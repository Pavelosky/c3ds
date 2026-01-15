"""
Serializers for device management.
File: apps/device_management/serializers.py

Three serializers for different use cases:
- DeviceListSerializer: Fast, minimal fields for list views
- DeviceDetailSerializer: Full info for single device page
- DeviceRegistrationSerializer: Only fields user can set when registering
"""

from rest_framework import serializers
from apps.device_management.models import Device
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
        "certificate_algorithm": "ECDSA_P256",
        "algorithm_display": "ECDSA P-256 (secp256r1)",
        "certificate_available": false,
        "certificate_expiry": "2025-01-14T10:00:00Z",
        "created_at": "2024-01-14T10:00:00Z",
        "updated_at": "2024-01-14T10:00:00Z",
        "message_count": 42
    }
    """
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    algorithm_display = serializers.CharField(source='get_certificate_algorithm_display', read_only=True)
    certificate_available = serializers.SerializerMethodField()
    message_count = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = [
            'id',
            'name',
            'device_type',
            'status',
            'status_display',
            'certificate_algorithm',
            'algorithm_display',
            'certificate_available',
            'certificate_expiry',
            'created_at',
            'updated_at',
            'message_count',
        ]

    def get_certificate_available(self, obj):
        """Check if certificate download is available (24-hour window)."""
        return obj.is_certificate_available_for_download()

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
        "certificate_algorithm": "ECDSA_P256",
        "algorithm_display": "ECDSA P-256 (secp256r1)",
        "certificate_serial": "1a2b3c4d5e6f",
        "certificate_expiry": "2025-01-14T10:00:00Z",
        "certificate_available": false,
        "created_by": {
            "id": 1,
            "username": "participant1",
            "email": "participant@example.com",
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
    algorithm_display = serializers.CharField(source='get_certificate_algorithm_display', read_only=True)
    created_by = UserSerializer(read_only=True)
    certificate_available = serializers.SerializerMethodField()
    message_count = serializers.SerializerMethodField()
    recent_messages = serializers.SerializerMethodField()

    class Meta:
        model = Device
        fields = [
            'id',
            'name',
            'device_type',
            'location',
            'status',
            'status_display',
            'certificate_algorithm',
            'algorithm_display',
            'certificate_serial',
            'certificate_expiry',
            'certificate_available',
            'created_by',
            'created_at',
            'updated_at',
            'message_count',
            'recent_messages',
        ]

    def get_certificate_available(self, obj):
        """Check if certificate download is available (24-hour window)."""
        return obj.is_certificate_available_for_download()

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
    class Meta:
        model = Device
        fields = [
            'name',
            'device_type',
            'location',
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

    def create(self, validated_data):
        """
        Create device with PENDING status.
        created_by will be set in view from request.user.
        """
        validated_data['status'] = 'PENDING'
        return super().create(validated_data)