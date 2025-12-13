from django.db import models
from apps.device_management.models import Device

# Create your models here.

class DeviceMessage(models.Model):
    """
    Model to store messages sent by devices.
    """
    device = models.ForeignKey(
        Device, 
        on_delete=models.CASCADE, 
        related_name='messages',
        db_index=True
    )
    
    # Message metadata
    message_type = models.CharField(max_length=50)
    timestamp = models.DateTimeField(db_index=True)
    data = models.JSONField(default=dict)

    # Logging trail
    recieved_at = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    certificate_serial = models.CharField(max_length=40, null=True, blank=True)

    class Meta:
        ordering = ['-recieved_at']
        verbose_name = 'Device Message'
        verbose_name_plural = 'Device Messages'

    def __str__(self):
        return f"Message from {self.device.name} - {self.message_type} at {self.timestamp}"
