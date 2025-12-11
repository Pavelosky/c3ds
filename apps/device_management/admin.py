from django.contrib import admin
from .models import Device, DeviceStatus
from django.contrib import messages
from django.http import HttpResponse
from .utils import generate_device_certificate
import zipfile
import io
from django.conf import settings

# Register your models here.


def generate_certificate_action(modeladmin, request, queryset):
    """
    Admin action to generate certificate for a single device and download it.
    """
    # Check if exactly one device is selected
    if queryset.count() != 1:
        messages.error(request, 'Please select exactly one device to generate a certificate.')
        return
    
    device = queryset.first()
    
    # Check if device already has a certificate
    if device.certificate_pem:
        messages.warning(request, f'Device "{device.name}" already has a certificate.')
        return
    
    # Generate certificate
    cert_pem, private_key_pem, serial_hex, expiry_date = generate_device_certificate(device)
    
    # Update device record (but NOT storing private key)
    device.certificate_pem = cert_pem
    device.certificate_serial = serial_hex
    device.certificate_expiry = expiry_date
    device.status = DeviceStatus.ACTIVE
    device.save()

    # Load CA certificate for inclusion in bundle
    with open(settings.CA_CERTIFICATE_PATH, 'rb') as f:
        ca_cert_pem = f.read().decode('utf-8')

    # Create a ZIP file in memory
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr(f'{device.name}_certificate.pem', cert_pem)
        zip_file.writestr(f'{device.name}_private_key.pem', private_key_pem)
        zip_file.writestr('ca_certificate.pem', ca_cert_pem)

        # README file with instructions
        readme_content = f"""Certificate Bundle for Device: {device.name}
                            Device ID: {device.id}
                            Generated: {device.created_at}
                            Certificate Serial: {serial_hex}
                            Valid Until: {expiry_date}

                            Files in this bundle:
                            - device_certificate.pem: Device's public certificate
                            - device_private_key.pem: Device's private key (KEEP SECURE!)
                            - ca_certificate.pem: Certificate Authority certificate

                            Installation Instructions:
                            1. Copy all three files to your device
                            2. Configure your device to use these certificates for authentication
                            3. IMPORTANT: Store the private key securely and never share it

                            WARNING: This private key is not stored on the server. 
                            If you lose it, you must generate a new certificate.
                            """
        zip_file.writestr('README.txt', readme_content)
    
    # Prepare HTTP response with ZIP file
    zip_buffer.seek(0)
    response = HttpResponse(zip_buffer, content_type='application/zip')
    response['Content-Disposition'] = f'attachment; filename={device.name}_certificate_bundle.zip'

    return response

generate_certificate_action.short_description = "Generate certificates for selected devices"


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'status', 'certificate_serial', 'certificate_expiry', 'created_at', 'updated_at')
    list_filter = ('status', 'created_at', 'updated_at')
    search_fields = ('name', 'id' 'certificate_serial')
    readonly_fields = ('id', 'created_at', 'updated_at', 'created_by')
    actions = [generate_certificate_action]

