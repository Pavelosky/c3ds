#include "network.h"
#include "config.h"
#include "hardware.h"
#include <ESP8266WiFi.h>
#include <time.h>

// ============================================================================
// INTERNAL STATE VARIABLES
// ============================================================================

static bool timeInitialized = false;
static unsigned long bootTime = 0;  // Time when device booted

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

bool initializeWiFi() {
    Serial.println("\n[NET] ═══════════════════════════════════");
    Serial.println("[NET] Initializing WiFi Connection");
    Serial.println("[NET] ═══════════════════════════════════");
    
    // Set WiFi mode to station (client)
    WiFi.mode(WIFI_STA);
    
    // Disconnect any previous connection
    WiFi.disconnect();
    delay(100);
    
    // Start connection
    Serial.print("[NET] Connecting to: ");
    Serial.println(WIFI_SSID);
    Serial.print("[NET] ");
    
    WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
    
    // Wait for connection with timeout
    unsigned long startAttempt = millis();
    
    while (WiFi.status() != WL_CONNECTED) {
        // Check for timeout
        if (millis() - startAttempt >= WIFI_TIMEOUT) {
            Serial.println("\n[NET] ✗ WiFi connection timeout!");
            setWiFiLED(false);
            return false;
        }
        
        // Visual progress indicator
        Serial.print(".");
        setWiFiLED(true);
        delay(250);
        setWiFiLED(false);
        delay(250);
    }
    
    Serial.println("\n[NET] ✓ WiFi connected!");
    Serial.print("[NET] IP Address: ");
    Serial.println(WiFi.localIP());
    Serial.print("[NET] MAC Address: ");
    Serial.println(WiFi.macAddress());
    Serial.print("[NET] Signal Strength: ");
    Serial.print(WiFi.RSSI());
    Serial.println(" dBm");
    
    // Keep WiFi LED on when connected
    setWiFiLED(true);
    
    return true;
}

bool isWiFiConnected() {
    return WiFi.status() == WL_CONNECTED;
}

bool reconnectWiFi() {
    if (isWiFiConnected()) {
        return true;  // Already connected
    }
    
    Serial.println("\n[NET] WiFi connection lost! Attempting reconnection...");
    setWiFiLED(false);
    
    return initializeWiFi();
}

bool initializeNTP() {
    if (!isWiFiConnected()) {
        Serial.println("[NET] ✗ Cannot initialize NTP - WiFi not connected");
        return false;
    }
    
    Serial.println("\n[NET] ═══════════════════════════════════");
    Serial.println("[NET] Synchronizing Time with NTP");
    Serial.println("[NET] ═══════════════════════════════════");
    Serial.print("[NET] NTP Server: ");
    Serial.println(NTP_SERVER);
    
    // Configure NTP
    configTime(GMT_OFFSET_SEC, DAYLIGHT_OFFSET_SEC, NTP_SERVER);
    
    // Wait for time to be set (with timeout)
    Serial.print("[NET] Waiting for time sync");
    int attempts = 0;
    const int maxAttempts = 20;  // 10 seconds timeout
    
    while (time(nullptr) < 100000 && attempts < maxAttempts) {
        Serial.print(".");
        delay(500);
        attempts++;
    }
    
    if (attempts >= maxAttempts) {
        Serial.println("\n[NET] ✗ NTP synchronization timeout!");
        timeInitialized = false;
        return false;
    }
    
    Serial.println("\n[NET] ✓ Time synchronized!");
    
    // Get current time
    time_t now = time(nullptr);
    struct tm* timeinfo = gmtime(&now);
    
    Serial.print("[NET] Current UTC time: ");
    Serial.printf("%04d-%02d-%02d %02d:%02d:%02d\n",
                  timeinfo->tm_year + 1900,
                  timeinfo->tm_mon + 1,
                  timeinfo->tm_mday,
                  timeinfo->tm_hour,
                  timeinfo->tm_min,
                  timeinfo->tm_sec);
    
    timeInitialized = true;
    bootTime = now;
    
    return true;
}

bool isTimeInitialized() {
    return timeInitialized;
}

String getCurrentTimestamp() {
    if (!timeInitialized) {
        return "1970-01-01T00:00:00Z";  // Epoch time (indicates not initialized)
    }
    
    time_t now = time(nullptr);
    struct tm* timeinfo = gmtime(&now);
    
    // Format: 2025-01-18T14:30:45Z (ISO 8601)
    char timestamp[25];
    snprintf(timestamp, sizeof(timestamp),
             "%04d-%02d-%02dT%02d:%02d:%02dZ",
             timeinfo->tm_year + 1900,
             timeinfo->tm_mon + 1,
             timeinfo->tm_mday,
             timeinfo->tm_hour,
             timeinfo->tm_min,
             timeinfo->tm_sec);
    
    return String(timestamp);
}

int getWiFiRSSI() {
    if (!isWiFiConnected()) {
        return -100;  // Very weak signal indicator
    }
    return WiFi.RSSI();
}

unsigned long getUptimeSeconds() {
    if (!timeInitialized) {
        return millis() / 1000;  // Fallback to millis if time not initialized
    }
    
    time_t now = time(nullptr);
    return now - bootTime;
}

void printNetworkDiagnostics() {
    Serial.println("\n[NET] ═══════════════════════════════════");
    Serial.println("[NET] Network Diagnostics");
    Serial.println("[NET] ═══════════════════════════════════");
    
    // WiFi status
    Serial.print("[NET] WiFi Status: ");
    if (isWiFiConnected()) {
        Serial.println("✓ Connected");
        Serial.print("[NET] SSID: ");
        Serial.println(WiFi.SSID());
        Serial.print("[NET] IP Address: ");
        Serial.println(WiFi.localIP());
        Serial.print("[NET] MAC Address: ");
        Serial.println(WiFi.macAddress());
        Serial.print("[NET] Signal Strength: ");
        Serial.print(WiFi.RSSI());
        Serial.println(" dBm");
    } else {
        Serial.println("✗ Disconnected");
    }
    
    // Time synchronization
    Serial.print("[NET] Time Sync: ");
    if (timeInitialized) {
        Serial.println("✓ Synchronized");
        Serial.print("[NET] Current Time: ");
        Serial.println(getCurrentTimestamp());
    } else {
        Serial.println("✗ Not synchronized");
    }
    
    // Uptime
    Serial.print("[NET] Uptime: ");
    Serial.print(getUptimeSeconds());
    Serial.println(" seconds");
    
    // Memory
    Serial.print("[NET] Free Heap: ");
    Serial.print(ESP.getFreeHeap());
    Serial.println(" bytes");
    
    Serial.println("[NET] ═══════════════════════════════════\n");
}