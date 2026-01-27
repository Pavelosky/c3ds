#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

// ============================================================================
// NETWORK CONFIGURATION
// ============================================================================

static const char* WIFI_SSID = "your_network_name";
static const char* WIFI_PASSWORD = "your_wifi_password";

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

static const char* DEVICE_ID = "your_device_id-dynamically_generated";

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
static const char* DEVICE_CERTIFICATE_B64 ="your_certificate - dynamically_generated";

// ECDSA P-256 Private Key (32 bytes)
// Note: Cannot use #define for arrays, must use static const in this case
static const uint8_t ECDSA_PRIVATE_KEY[32] = {
    your, private, key, bytes, here,
};

#endif // CONFIG_H
