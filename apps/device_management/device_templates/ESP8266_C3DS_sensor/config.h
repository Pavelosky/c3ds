#ifndef CONFIG_H
#define CONFIG_H

// ============================================================================
// NETWORK CONFIGURATION
// ============================================================================

static const char* WIFI_SSID = "TechLabNet";
static const char* WIFI_PASSWORD = "BC6V6DE9A8T9";

static const char* SERVER_URL = "http://192.168.1.102:8000/api/device/message/";

// NTP (Network Time Protocol) for timestamps
static const char* NTP_SERVER = "pool.ntp.org";
static const long GMT_OFFSET_SEC = 0;           // UTC
static const int DAYLIGHT_OFFSET_SEC = 0;

// ============================================================================
// DEVICE IDENTITY
// ============================================================================

static const char* DEVICE_ID = "0bfaab4a-592b-4b7b-ae95-4a05a9be311f";

// ============================================================================
// HARDWARE PINS (NodeMCU/Wemos D1 Mini)
// ============================================================================

static const int BUTTON_PIN = 14;              // D5 - Alert button
static const int STATUS_LED_PIN = 12;          // D6 - Status indicator
static const int BUILTIN_LED_PIN = 2;          // D4 - WiFi indicator (inverted logic)

// ============================================================================
// TIMING CONFIGURATION
// ============================================================================

static const unsigned long HEARTBEAT_INTERVAL = 20000;    // 20 seconds
static const unsigned long DEBOUNCE_DELAY = 50;           // 50ms
static const unsigned long MIN_PRESS_INTERVAL = 2000;     // 2 seconds between button presses

static const unsigned long WIFI_TIMEOUT = 20000;          // 20 seconds
static const unsigned long HTTP_TIMEOUT = 10000;          // 10 seconds

// ============================================================================
// CRYPTOGRAPHIC CREDENTIALS
// ============================================================================

// Device Certificate (Base64 encoded - sent in X-Device-Certificate header)
// This is the PEM certificate, Base64-encoded for transmission in HTTP header
static const char* DEVICE_CERTIFICATE_B64 ="LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURkRENDQVZ5Z0F3SUJBZ0lVVGdoaVZvVnhWeVJrd2czYXhYSVpjKzNQdEd3d0RRWUpLb1pJaHZjTkFRRUwKQlFBd1RqRUxNQWtHQTFVRUJoTUNSVlV4RHpBTkJnTlZCQWdNQmtWMWNtOXdaVEVYTUJVR0ExVUVDZ3dPUXpORQpVeUJRY205MGIzUjVjR1V4RlRBVEJnTlZCQU1NREVNelJGTWdVbTl2ZENCRFFUQWVGdzB5TmpBeE1UQXhNVEF3Ck16WmFGdzB5TnpBeE1UQXhNVEF3TXpaYU1GTXhDekFKQmdOVkJBWVRBa1ZWTVJVd0V3WURWUVFLREF4RE0wUlQKSUU1bGRIZHZjbXN4TFRBckJnTlZCQU1NSkRCaVptRmhZalJoTFRVNU1tSXROR0kzWWkxaFpUazFMVFJoTURWaApPV0psTXpFeFpqQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJCeUFqV1QzMGdaeDRpSmNGaDdECkhOQmlWM0pGZzdZTXRsMlRUaitvbmYydEc3aG1VK1pmc1lOOUlIQ2RkVmhCYjgvWUpRbCtURXpvVVg3SDNsdjIKS2U2akVEQU9NQXdHQTFVZEV3RUIvd1FDTUFBd0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dJQkFCRXAvd1JHZDFrYwpFV2NIc0QrMCthTUMwRzQ2VEVvb3h0T0tzdTJSbVpnSmZHVXFoTXovSUhwMmN6RkdhTlpLSnhlNVQwSnZ6ckJTCnptUy9EemxhS2M0OXhlalFqckVRbUJSckJzM0tOak9yNndDTzdxS2l1bUNKSElGRnNYTDBCUnFZTno2OC9ob3QKT0lpbXRoREVlVUVuRVREcC9KNHQ3bERVaEdqdDcrUVRYdGt3L3lhbXBkOXo3NURNV28wT0h3SXduejJoZVBEdAplS2J3dzRvK2FxS0JHQ0RQSTU1UmIzS3NCZU9kejZEZDFEUnYrSjd5ZEFQb0kzSnFHUXFYV2c4b1A0WG9rNVhzCjV3Yk5GUGRHN0gwSTI1eUFQTUo2SWxibTBEZnVwUmhlUkdjRmVEYy9IK0M0Vld1dWhOSFZ6Qmc2bDVLdC9Rc3AKWEQxMDRUVUEzdnlOa0NlekRSNnVwamR2R0NEcXIvTVBZRWthWStSdWxSUEhHUmRxUFBQSlZ4eGZIRHJVYVd1agp4Nm9Qam1vUUUzQTFaSmIzNEJuUlg1VWluWFBZU0o2NmVyOEs3WHp1cHFrUzZvMkk4aUc4ek9sQ0xZNC9lU2h1CmZWR0FUdGFPUnA3QUJUbVB3NTdBbjQ3eThtZkoxaTVYVU95Q3U5WXF4ZUFTcy96SE5waFlLNjNRUWlWeDRSTmIKTGRRNjFjRFNqTXFPNnNCbkNUU29OaTd1Y3ZRci9jK3RsUURPWFdCM1NKRlNkMW8xTzEyRjBObVM5T01qdWwvSQp5MythT2ptelExd3BoRHFYMTFEc0ZBZm1HY0N3bDhKRmwyZ1FkUXk2elFaZjhlK1VOZndiZ01QS1NhT1M0Y2pOCkg3ck9UdmRLU0t2eWlZcHA3NklaV0R3WXdoekZjYWgvCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K";

// ECDSA P-256 Private Key (32 bytes)
static const uint8_t ECDSA_PRIVATE_KEY[32] = {
    0xe4, 0x87, 0x72, 0x9c, 0x2d, 0x83, 0x67, 0xe6,
    0xec, 0x08, 0x0f, 0xb1, 0xbd, 0x8f, 0xf5, 0xed,
    0xba, 0xd6, 0x7f, 0xed, 0xd5, 0x99, 0xca, 0xb8,
    0xdd, 0xfd, 0x09, 0x28, 0x1d, 0x0a, 0x85, 0x36
};

#endif // CONFIG_H
