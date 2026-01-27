import zipfile
import io
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.http import HttpResponseForbidden, HttpResponse
from django.utils import timezone
from datetime import timedelta
from apps.core.permissions import participant_required
from .models import Device, DeviceStatus
from .forms import DeviceRegistrationForm, DeviceConfigForm
from .utils import generate_device_certificate


# Path to device template files
ESP8266_SENSOR_BASE_DIR = Path(__file__).parent / 'device_templates' / 'ESP8266_sensor'
DEVICE_TEMPLATES_DIR = ESP8266_SENSOR_BASE_DIR / 'ESP8266_P256'


@participant_required
def participant_dashboard(request):
    """Dashboard for system participants to manage their own devices"""
    # Get only devices owned by this participant
    my_devices = Device.objects.filter(created_by=request.user).order_by('-created_at')

    context = {
        'devices': my_devices,
    }

    return render(request, 'device_management/participant_dashboard.html', context)


@participant_required
def add_device(request):
    """
    View for participants to register a new device.
    Creates device with status=PENDING, ready for certificate generation.
    """
    if request.method == 'POST':
        # Pass the current user to the form for duplicate name checking
        form = DeviceRegistrationForm(request.POST, user=request.user)

        if form.is_valid():
            # Create device but don't save yet
            device = form.save(commit=False)

            # Set the owner to current user
            device.created_by = request.user

            # Set initial status to PENDING (waiting for certificate generation)
            device.status = DeviceStatus.PENDING

            # Save the device
            device.save()

            messages.success(
                request,
                f'Device "{device.name}" has been registered successfully! '
                f'Status: {device.get_status_display()}'
            )

            return redirect('participant:dashboard')
    else:
        # GET request - show empty form
        form = DeviceRegistrationForm(user=request.user)

    context = {
        'form': form,
    }

    return render(request, 'device_management/add_device.html', context)


@participant_required
def remove_device(request, device_id):
    """
    Soft delete: Sets device status to REVOKED.
    Only allows participants to remove their own devices.
    Requires POST request with CSRF token for security.
    """
    # Only accept POST requests
    if request.method != 'POST':
        messages.error(request, 'Invalid request method.')
        return redirect('participant:dashboard')

    # Get device and verify it exists
    device = get_object_or_404(Device, id=device_id)

    # Security check: Ensure user owns this device
    if device.created_by != request.user:
        messages.error(request, 'You do not have permission to remove this device.')
        return HttpResponseForbidden('You do not have permission to remove this device.')

    # Check if device is already revoked
    if device.status == DeviceStatus.REVOKED:
        messages.warning(request, f'Device "{device.name}" is already revoked.')
        return redirect('participant:dashboard')

    # Soft delete: change status to REVOKED
    device.status = DeviceStatus.REVOKED
    device.save()

    messages.success(
        request,
        f'Device "{device.name}" has been removed (revoked). '
        f'It can no longer send messages to the system.'
    )

    return redirect('participant:dashboard')


@participant_required
def generate_certificate(request, device_id):
    """
    Generate certificate and private key for a device.
    Only allows participants to generate certificates for their own devices.
    Requires POST request with CSRF token for security.
    Status remains PENDING - admin must activate device.
    """
    # Only accept POST requests
    if request.method != 'POST':
        messages.error(request, 'Invalid request method.')
        return redirect('participant:dashboard')

    # Get device and verify it exists
    device = get_object_or_404(Device, id=device_id)

    # Security check: Ensure user owns this device
    if device.created_by != request.user:
        messages.error(request, 'You do not have permission to generate a certificate for this device.')
        return HttpResponseForbidden('You do not have permission to generate a certificate for this device.')

    # Check if device is revoked
    if device.status == DeviceStatus.REVOKED:
        messages.error(request, f'Cannot generate certificate for revoked device "{device.name}".')
        return redirect('participant:dashboard')

    # Generate certificate
    try:
        cert_pem, key_pem, serial_hex, expiry_date = generate_device_certificate(device)

        # Store certificate information and private key
        device.certificate_pem = cert_pem
        device.private_key_pem = key_pem
        device.certificate_serial = serial_hex
        device.certificate_expiry = expiry_date
        device.certificate_generated_at = timezone.now()
        device.save()

        messages.success(
            request,
            f'Certificate generated successfully for device "{device.name}"! '
            f'You can download the certificate and private key for the next 24 hours. '
            f'Status remains PENDING until admin activates the device.'
        )
    except Exception as e:
        messages.error(request, f'Error generating certificate: {str(e)}')

    return redirect('participant:dashboard')


@participant_required
def download_certificate(request, device_id):
    """
    Download device certificate (.pem file).
    Only available for 24 hours after generation.
    """
    # Get device and verify it exists
    device = get_object_or_404(Device, id=device_id)

    # Security check: Ensure user owns this device
    if device.created_by != request.user:
        messages.error(request, 'You do not have permission to download this certificate.')
        return HttpResponseForbidden('You do not have permission to download this certificate.')

    # Check if certificate exists
    if not device.certificate_pem or not device.certificate_generated_at:
        messages.error(request, f'No certificate available for device "{device.name}". Please generate one first.')
        return redirect('participant:dashboard')

    # Check if download window has expired (24 hours)
    expiry_window = device.certificate_generated_at + timedelta(hours=24)
    if timezone.now() > expiry_window:
        messages.error(
            request,
            f'Certificate download window expired for device "{device.name}". '
            f'Please regenerate the certificate.'
        )
        return redirect('participant:dashboard')

    # Create HTTP response with certificate file
    response = HttpResponse(device.certificate_pem, content_type='application/x-pem-file')
    response['Content-Disposition'] = f'attachment; filename="{device.name}_certificate.pem"'

    return response


@participant_required
def download_private_key(request, device_id):
    """
    Download device private key (.key file).
    Only available for 24 hours after generation.
    WARNING: Private key is stored temporarily and should be handled securely.
    """
    # Get device and verify it exists
    device = get_object_or_404(Device, id=device_id)

    # Security check: Ensure user owns this device
    if device.created_by != request.user:
        messages.error(request, 'You do not have permission to download this private key.')
        return HttpResponseForbidden('You do not have permission to download this private key.')

    # Check if certificate/key exists
    if not device.private_key_pem or not device.certificate_generated_at:
        messages.error(request, f'No private key available for device "{device.name}". Please generate a certificate first.')
        return redirect('participant:dashboard')

    # Check if download window has expired (24 hours)
    expiry_window = device.certificate_generated_at + timedelta(hours=24)
    if timezone.now() > expiry_window:
        messages.error(
            request,
            f'Private key download window expired for device "{device.name}". '
            f'Please regenerate the certificate.'
        )
        return redirect('participant:dashboard')

    # Create HTTP response with private key file
    response = HttpResponse(device.private_key_pem, content_type='application/x-pem-file')
    response['Content-Disposition'] = f'attachment; filename="{device.name}_private.key"'

    return response


def _extract_private_key_bytes(private_key_pem: str) -> list[int]:
    """
    Extract raw private key bytes from PEM-encoded ECDSA private key.
    Returns list of integers for use in C/Arduino config.h file.
    """
    # Load the private key from PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )

    # Get the raw private key bytes (32 bytes for P-256)
    private_numbers = private_key.private_numbers()
    private_bytes = private_numbers.private_value.to_bytes(32, byteorder='big')

    return list(private_bytes)


def _generate_config_h(device, wifi_ssid: str, wifi_password: str) -> str:
    """
    Generate config.h content with device-specific credentials.
    """
    # Extract private key bytes for the C array
    key_bytes = _extract_private_key_bytes(device.private_key_pem)

    # Format key bytes as C hex array (8 per line)
    key_lines = []
    for i in range(0, len(key_bytes), 8):
        chunk = key_bytes[i:i+8]
        hex_values = ', '.join(f'0x{b:02x}' for b in chunk)
        key_lines.append(f'    {hex_values}')
    key_array = ',\n'.join(key_lines)

    # Base64 encode the certificate for HTTP header transmission
    cert_b64 = base64.b64encode(device.certificate_pem.encode('utf-8')).decode('utf-8')

    config_content = f'''#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

// ============================================================================
// NETWORK CONFIGURATION
// ============================================================================

static const char* WIFI_SSID = "{wifi_ssid}";
static const char* WIFI_PASSWORD = "{wifi_password}";

static const char* SERVER_URL = "http://192.168.1.102:8000/api/device/message/";

// NTP (Network Time Protocol) for timestamps
static const char* NTP_SERVER = "pool.ntp.org";
static const long GMT_OFFSET_SEC = 0;           // UTC
static const int DAYLIGHT_OFFSET_SEC = 0;

// NTP Synchronization
static const unsigned long MIN_VALID_UNIX_TIMESTAMP = 100000;  // Jan 2, 1970 threshold
static const int NTP_MAX_SYNC_ATTEMPTS = 20;                   // Maximum retry attempts

// ============================================================================
// DEVICE IDENTITY
// ============================================================================

static const char* DEVICE_ID = "{device.id}";

// ============================================================================
// HARDWARE PINS (NodeMCU/Wemos D1 Mini)
// ============================================================================

// HC-SR04 Ultrasonic Sensor
static const int SENSOR_TRIG_PIN = 5;         // D1 - HC-SR04 Trigger pin
static const int SENSOR_ECHO_PIN = 4;         // D2 - HC-SR04 Echo pin

// LED Indicators
static const int STATUS_LED_PIN = 12;         // D6 - Status indicator
static const int BUILTIN_LED_PIN = 2;         // D4 - WiFi indicator (inverted logic)

// ============================================================================
// TIMING CONFIGURATION
// ============================================================================

static const unsigned long HEARTBEAT_INTERVAL = 20000;    // 20 seconds
static const unsigned long SENSOR_POLL_INTERVAL = 500;    // 500ms - Check sensor twice per second
static const unsigned long ALERT_INTERVAL = 10000;        // 10 seconds - Send alert every 10s while detecting

static const unsigned long WIFI_TIMEOUT = 20000;          // 20 seconds
static const unsigned long HTTP_TIMEOUT = 10000;          // 10 seconds

// ============================================================================
// SENSOR CONFIGURATION (HC-SR04)
// ============================================================================

// Distance thresholds
#define DETECTION_THRESHOLD_CM 25.0         // Alert when object <= 25cm
#define DETECTION_HYSTERESIS_CM 2.0         // Deactivate when object > 27cm
#define SENSOR_MAX_DISTANCE_CM 400.0        // HC-SR04 max reliable range

// Error handling
#define CONSECUTIVE_READINGS_REQUIRED 2       // Require 2 consecutive valid readings

// Physics constants
#define SPEED_OF_SOUND_CM_PER_MICROSECOND 0.0343  // Speed of sound at 20°C (343 m/s = 0.0343 cm/μs)
#define SENSOR_PULSE_TIMEOUT_MICROSECONDS 30000   // 30ms timeout (~500cm max range)
#define SENSOR_MIN_DISTANCE_CM 2.0                 // Minimum reliable distance for HC-SR04

// ============================================================================
// MESSAGE BUFFER CONFIGURATION
// ============================================================================

// JSON document capacity for ArduinoJson library
#define MESSAGE_JSON_DOC_SIZE 512                 // Bytes allocated for JSON serialization

// Timestamp buffer size
#define TIMESTAMP_BUFFER_SIZE 25                  // ISO 8601 format: "YYYY-MM-DDTHH:MM:SSZ" + null terminator

// ============================================================================
// CRYPTOGRAPHIC CREDENTIALS
// ============================================================================

// Device Certificate (Base64 encoded - sent in X-Device-Certificate header)
// This is the PEM certificate, Base64-encoded for transmission in HTTP header
static const char* DEVICE_CERTIFICATE_B64 ="{cert_b64}";

// ECDSA P-256 Private Key (32 bytes)
static const uint8_t ECDSA_PRIVATE_KEY[32] = {{
{key_array}
}};

#endif // CONFIG_H
'''
    return config_content


@participant_required
def download_device_code(request, device_id):
    """
    Download pre-configured ESP8266 code bundle as ZIP file.

    GET: Shows form for WiFi credentials
    POST: Generates ZIP with config.h containing device credentials

    Only available for devices with generated certificates within 24-hour window.
    """
    device = get_object_or_404(Device, id=device_id)

    # Security check: Ensure user owns this device
    if device.created_by != request.user:
        messages.error(request, 'You do not have permission to download code for this device.')
        return HttpResponseForbidden('You do not have permission to download code for this device.')

    # Check if certificate exists
    if not device.certificate_pem or not device.private_key_pem or not device.certificate_generated_at:
        messages.error(
            request,
            f'No certificate available for device "{device.name}". '
            f'Please generate a certificate first.'
        )
        return redirect('participant:dashboard')

    # Check if download window has expired (24 hours)
    expiry_window = device.certificate_generated_at + timedelta(hours=24)
    if timezone.now() > expiry_window:
        messages.error(
            request,
            f'Download window expired for device "{device.name}". '
            f'Please regenerate the certificate.'
        )
        return redirect('participant:dashboard')

    if request.method == 'POST':
        form = DeviceConfigForm(request.POST)
        if form.is_valid():
            wifi_ssid = form.cleaned_data['wifi_ssid']
            wifi_password = form.cleaned_data['wifi_password']

            # Generate config.h content
            config_content = _generate_config_h(device, wifi_ssid, wifi_password)

            # Create ZIP file in memory
            zip_buffer = io.BytesIO()
            with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                # Add README.md from parent ESP8266_sensor directory (shared across variants)
                readme_path = ESP8266_SENSOR_BASE_DIR / 'README.md'
                if readme_path.exists():
                    zip_file.write(readme_path, 'README.md')

                # Add config.h (generated)
                zip_file.writestr('ESP8266_P256/config.h', config_content)

                # Add all template files from the specific variant directory
                if DEVICE_TEMPLATES_DIR.exists():
                    for file_path in DEVICE_TEMPLATES_DIR.iterdir():
                        if file_path.is_file() and file_path.name != 'config.h':
                            zip_file.write(
                                file_path,
                                f'ESP8266_P256/{file_path.name}'
                            )

            # Prepare response
            zip_buffer.seek(0)
            response = HttpResponse(zip_buffer.read(), content_type='application/zip')
            safe_name = device.name.replace(' ', '_')
            response['Content-Disposition'] = f'attachment; filename="{safe_name}_ESP8266_code.zip"'

            return response
    else:
        form = DeviceConfigForm()

    context = {
        'form': form,
        'device': device,
    }

    return render(request, 'device_management/download_device_code.html', context)
