from django.contrib import admin
from .models import (
    AnomalyFlag,
    DeviceIPHistory,
    Incident,
    IncidentNote,
    DeviceCommand,
    DetectionPolicy,
    PolicyTriggerLog,
)


@admin.register(AnomalyFlag)
class AnomalyFlagAdmin(admin.ModelAdmin):
    list_display = ('device', 'flag_type', 'severity', 'is_resolved', 'raised_at')
    list_filter = ('flag_type', 'severity', 'raised_at')
    search_fields = ('device__name', 'explanation')
    readonly_fields = ('raised_at',)


@admin.register(DeviceIPHistory)
class DeviceIPHistoryAdmin(admin.ModelAdmin):
    list_display = ('device', 'ip_address', 'first_seen', 'last_seen')
    search_fields = ('device__name', 'ip_address')
    readonly_fields = ('first_seen', 'last_seen')


class IncidentNoteInline(admin.TabularInline):
    model = IncidentNote
    extra = 0
    readonly_fields = ('author', 'created_at')


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'incident_status', 'created_by', 'created_at')
    list_filter = ('severity', 'incident_status')
    search_fields = ('title', 'description')
    readonly_fields = ('created_at', 'updated_at')
    inlines = [IncidentNoteInline]


@admin.register(IncidentNote)
class IncidentNoteAdmin(admin.ModelAdmin):
    list_display = ('incident', 'author', 'created_at')
    search_fields = ('incident__title', 'author__username', 'content')
    readonly_fields = ('created_at',)


@admin.register(DeviceCommand)
class DeviceCommandAdmin(admin.ModelAdmin):
    list_display = ('device', 'action', 'status', 'issued_by', 'created_at', 'expires_at')
    list_filter = ('action', 'status')
    search_fields = ('device__name',)
    readonly_fields = ('id', 'created_at', 'delivered_at', 'acknowledged_at')


@admin.register(DetectionPolicy)
class DetectionPolicyAdmin(admin.ModelAdmin):
    list_display = ('name', 'condition_type', 'action_type', 'is_active', 'created_at')
    list_filter = ('condition_type', 'action_type', 'is_active')
    search_fields = ('name', 'description')
    readonly_fields = ('id', 'created_at', 'updated_at')


@admin.register(PolicyTriggerLog)
class PolicyTriggerLogAdmin(admin.ModelAdmin):
    list_display = ('policy', 'device', 'triggered_at')
    list_filter = ('triggered_at',)
    search_fields = ('policy__name', 'device__name')
    readonly_fields = ('id', 'policy', 'device', 'triggered_at', 'detail')
