import zipfile
import io
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from django.shortcuts import get_object_or_404
from django.http import HttpResponseForbidden, HttpResponse
from django.utils import timezone
from datetime import timedelta
from apps.core.permissions import participant_required
from .models import Device


# Path to device template files
ESP8266_SENSOR_BASE_DIR = Path(__file__).parent / 'device_templates' / 'ESP8266_sensor'
DEVICE_TEMPLATES_DIR = ESP8266_SENSOR_BASE_DIR / 'ESP8266_P256'


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
        return HttpResponseForbidden('You do not have permission to download this certificate.')

    # Check if certificate exists
    if not device.certificate_pem or not device.certificate_generated_at:
        return HttpResponse(
            f'No certificate available for device "{device.name}". Please generate one first.',
            status=404
        )

    # Check if download window has expired (24 hours)
    expiry_window = device.certificate_generated_at + timedelta(hours=24)
    if timezone.now() > expiry_window:
        return HttpResponse(
            f'Certificate download window expired for device "{device.name}". '
            f'Please regenerate the certificate.',
            status=410  # 410 Gone - resource no longer available
        )

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
        return HttpResponseForbidden('You do not have permission to download this private key.')

    # Check if certificate/key exists
    if not device.private_key_pem or not device.certificate_generated_at:
        return HttpResponse(
            f'No private key available for device "{device.name}". Please generate a certificate first.',
            status=404
        )

    # Check if download window has expired (24 hours)
    expiry_window = device.certificate_generated_at + timedelta(hours=24)
    if timezone.now() > expiry_window:
        return HttpResponse(
            f'Private key download window expired for device "{device.name}". '
            f'Please regenerate the certificate.',
            status=410  # 410 Gone - resource no longer available
        )

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
    Used by API endpoint for downloading ESP8266 code.
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
static const char* ACK_URL    = "http://192.168.1.102:8000/api/device/ack/";

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
