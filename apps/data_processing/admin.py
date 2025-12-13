from django.contrib import admin
from .models import DeviceMessage

# Register your models here.
@admin.register(DeviceMessage)
class DeviceMessageAdmin(admin.ModelAdmin):
    list_display = ('device', 
                    'message_type', 
                    'timestamp', 
                    'recieved_at', 
                    'ip_address')
    
    list_filter = ('message_type', 
                   'timestamp', 
                   'recieved_at')
    
    search_fields = ('device__name', 
                     'certificate_serial', 
                     'data',
                     'ip_address')

    ordering = ('-recieved_at',)