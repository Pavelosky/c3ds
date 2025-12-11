from django.db import models
from django.contrib.auth.models import User
import uuid


# Create your models here.
class DeviceStatus(models.TextChoices):
    ACTIVE = 'ACTIVE', 'Active'         #the device is active and operational
    PENDING = 'PENDING', 'Pending'      #the device is pending activation
    REVOKED = 'REVOKED', 'Revoked'      #the device has been revoked and is no longer valid
    EXPIRED = 'EXPIRED', 'Expired'      #the device's validity period has expired
    INACTIVE = 'INACTIVE', 'Inactive'   #the device is allowed but inactive and not currently in use

class Device(models.Model):
    # Primary identifier
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False
    )
    
    # Human-readable identification
    name = models.CharField(
        max_length=255,
        help_text="Friendly name for the device (e.g., 'Sensor-Vilnius-001')"
    )
    
    # Status tracking
    status = models.CharField(
        max_length=20,
        choices=DeviceStatus.choices,
        default=DeviceStatus.PENDING
    )

     # Certificate information
    """
    SQLite couldn't nadle the BigIntegerField well, so we comment it out for now and 
    replaced it with CharField to store serial number as hex string.
    Once PostgreSQL is used, we can switch back to BigIntegerField.
    """
    # certificate_serial = models.BigIntegerField(
    #     unique=True,
    #     null=True,
    #     blank=True,
    #     help_text="X.509 certificate serial number"
    # )

    certificate_serial = models.CharField(
        max_length=40,  # Hex representation of serial number
        unique=True,
        null=True,
        blank=True,
        help_text="X.509 certificate serial number (hex)"
    )
    
    certificate_expiry = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Certificate expiration date"
    )
    
    certificate_pem = models.TextField(
        null=True,
        blank=True,
        help_text="PEM-encoded certificate"
    )
     # Audit trail
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_devices'
    )
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Device"
        verbose_name_plural = "Devices"
    
    def __str__(self):
        return f"{self.name} ({self.status})"