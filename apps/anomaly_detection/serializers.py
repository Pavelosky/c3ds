"""
Serializers for anomaly detection and incident management API endpoints.
"""
from rest_framework import serializers
from django.contrib.auth.models import User

from .models import AnomalyFlag, Incident, IncidentNote
from apps.device_management.models import DeviceAuditEntry
from apps.data_processing.models import DeviceMessage


class AnomalyFlagSerializer(serializers.ModelSerializer):
    device_name = serializers.CharField(source='device.name', read_only=True, default=None)
    is_resolved = serializers.BooleanField(read_only=True)
    resolved_by_username = serializers.CharField(
        source='resolved_by.username', read_only=True, default=None
    )

    class Meta:
        model = AnomalyFlag
        fields = [
            'id', 'device', 'device_name', 'flag_type', 'severity',
            'explanation', 'detail', 'raised_at',
            'is_resolved', 'resolved_at', 'resolved_by', 'resolved_by_username',
        ]
        read_only_fields = [
            'id', 'raised_at', 'resolved_at', 'resolved_by',
            'is_resolved', 'device_name', 'resolved_by_username',
        ]


class AnomalySummarySerializer(serializers.Serializer):
    """
    Aggregated count of unresolved anomaly flags by type and severity.
    Used by US-09 (Anomaly Summary at a Glance).
    """
    flag_type = serializers.CharField()
    severity = serializers.CharField()
    count = serializers.IntegerField()


class IncidentNoteSerializer(serializers.ModelSerializer):
    author_username = serializers.CharField(source='author.username', read_only=True, default=None)

    class Meta:
        model = IncidentNote
        fields = ['id', 'content', 'author', 'author_username', 'created_at']
        read_only_fields = ['id', 'author', 'author_username', 'created_at']


class IncidentListSerializer(serializers.ModelSerializer):
    created_by_username = serializers.CharField(
        source='created_by.username', read_only=True, default=None
    )
    flag_count = serializers.SerializerMethodField()
    note_count = serializers.SerializerMethodField()

    class Meta:
        model = Incident
        fields = [
            'id', 'title', 'severity', 'incident_status',
            'created_by', 'created_by_username', 'created_at', 'updated_at',
            'flag_count', 'note_count',
        ]

    def get_flag_count(self, obj):
        return obj.linked_flags.count()

    def get_note_count(self, obj):
        return obj.notes.count()


class IncidentDetailSerializer(serializers.ModelSerializer):
    created_by_username = serializers.CharField(
        source='created_by.username', read_only=True, default=None
    )
    notes = IncidentNoteSerializer(many=True, read_only=True)
    linked_flags = AnomalyFlagSerializer(many=True, read_only=True)
    linked_flag_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=AnomalyFlag.objects.all(),
        source='linked_flags',
        write_only=True,
        required=False,
    )
    linked_message_ids = serializers.PrimaryKeyRelatedField(
        many=True,
        queryset=DeviceMessage.objects.all(),
        source='linked_messages',
        write_only=True,
        required=False,
    )

    class Meta:
        model = Incident
        fields = [
            'id', 'title', 'description', 'severity', 'incident_status',
            'created_by', 'created_by_username', 'created_at', 'updated_at',
            'linked_flags', 'linked_flag_ids',
            'linked_message_ids',
            'notes',
        ]
        read_only_fields = ['id', 'created_by', 'created_by_username', 'created_at', 'updated_at', 'notes', 'linked_flags']

    def create(self, validated_data):
        linked_flags = validated_data.pop('linked_flags', [])
        linked_messages = validated_data.pop('linked_messages', [])
        incident = Incident.objects.create(**validated_data)
        incident.linked_flags.set(linked_flags)
        incident.linked_messages.set(linked_messages)
        return incident

    def update(self, instance, validated_data):
        linked_flags = validated_data.pop('linked_flags', None)
        linked_messages = validated_data.pop('linked_messages', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if linked_flags is not None:
            instance.linked_flags.set(linked_flags)
        if linked_messages is not None:
            instance.linked_messages.set(linked_messages)
        return instance


class DeviceAuditEntrySerializer(serializers.ModelSerializer):
    triggered_by_username = serializers.CharField(
        source='triggered_by.username', read_only=True, default=None
    )

    class Meta:
        model = DeviceAuditEntry
        fields = [
            'id', 'event_type', 'description',
            'triggered_by', 'triggered_by_username',
            'triggered_at', 'metadata',
        ]
        read_only_fields = fields
