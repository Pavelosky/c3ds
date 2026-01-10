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

# Certificate algorithms choices - for devices with limited resources
class CertificateAlgorithm(models.TextChoices):
    ECDSA_P256 = 'ECDSA_P256', 'ECDSA P-256 (secp256r1)'
    ECDSA_P384 = 'ECDSA_P384', 'ECDSA P-384 (secp384r1)'
    RSA_2048 = 'RSA_2048', 'RSA-2048'
    RSA_4096 = 'RSA_4096', 'RSA-4096'
    

class DeviceType(models.Model):
    """
    Device type model for categorizing IoT devices.
    Admin can manage available device types from Django admin panel.
    """
    name = models.CharField(
        max_length=100,
        unique=True,
        help_text="Type of device (e.g., 'Raspberry Pi', 'ESP8266')"
    )

    class Meta:
        ordering = ['name']
        verbose_name = "Device Type"
        verbose_name_plural = "Device Types"

    def __str__(self):
        return self.name

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

    description = models.TextField(
        blank=True,
        null=True,
        help_text="Optional description or notes about the device"
    )

    # Device type
    device_type = models.ForeignKey(
        DeviceType,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='devices',
        help_text="Type of IoT device"
    )

    # Location information
    latitude = models.DecimalField(
        max_digits=9,
        decimal_places=6,
        null=True,
        blank=True,
        help_text="Latitude coordinate (-90 to 90)"
    )

    longitude = models.DecimalField(
        max_digits=9,
        decimal_places=6,
        null=True,
        blank=True,
        help_text="Longitude coordinate (-180 to 180)"
    )

    # Status tracking
    status = models.CharField(
        max_length=20,
        choices=DeviceStatus.choices,
        default=DeviceStatus.PENDING
    )

     # Certificate information


    # Certificate algorithm selection
    certificate_algorithm = models.CharField(
        max_length=20,
        choices=CertificateAlgorithm.choices,
        default=CertificateAlgorithm.ECDSA_P384,
        help_text="Cryptographic algorithm for device certificate (choose ECDSA for resource-constrained devices)"
    )

    """
    SQLite couldn't handle the BigIntegerField well, so we comment it out for now and 
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

    certificate_generated_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Timestamp when certificate was generated (for 24-hour download window)"
    )

    private_key_pem = models.TextField(
        null=True,
        blank=True,
        help_text="PEM-encoded private key (stored temporarily for 24-hour download window)"
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
    
    def is_certificate_available_for_download(self):
        """
        Check if the certificate and private key are available for download
        within the 24-hour window after generation.
        """
        if not self.certificate_generated_at:
            return False
        
        from django.utils import timezone
        from datetime import timedelta

        expiry_time = self.certificate_generated_at + timedelta(hours=24)
        return timezone.now() <= expiry_time