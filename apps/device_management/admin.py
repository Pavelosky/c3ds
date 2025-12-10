from django.contrib import admin
from .models import Device
# Register your models here.

@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'status', 'certificate_serial', 'certificate_expiry', 'created_at', 'updated_at')
    list_filter = ('status', 'created_at', 'updated_at')
    search_fields = ('name', 'id' 'certificate_serial')
    readonly_fields = ('id', 'created_at', 'updated_at', 'created_by')
    