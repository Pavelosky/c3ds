#include "config.h"
#include "messaging.h"
#include "network.h"
#include "crypto.h"
#include "hardware.h"
#include <ESP8266HTTPClient.h>
#include <WiFiClient.h>
#include <ArduinoJson.h>

// ============================================================================
// INTERNAL STATE VARIABLES
// ============================================================================

static unsigned long lastHeartbeatTime = 0;
static bool messagingReady = false;

// Runtime-mutable config (overrides compile-time constants via SET_INTERVAL / SET_THRESHOLD)
static unsigned long heartbeatIntervalMs  = HEARTBEAT_INTERVAL;
static float         detectionThresholdCm = DETECTION_THRESHOLD_CM;

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * Create JSON message payload
 *
 * @param type Message type (HEARTBEAT or ALERT)
 * @param distance Distance in cm (only for ALERT type)
 * @param durationSeconds Duration in seconds (only for ALERT type)
 * @param firstDetectedTimestamp ISO timestamp (only for ALERT type)
 * @return JSON string
 */
static String createMessagePayload(MessageType type, float distance = 0.0,
                                   unsigned long durationSeconds = 0,
                                   const String& firstDetectedTimestamp = "") {
    // Create JSON document
    // Size: Calculated based on expected message size
    StaticJsonDocument<MESSAGE_JSON_DOC_SIZE> doc;
    
    // Add common fields
    doc["device_id"] = DEVICE_ID;
    doc["timestamp"] = getCurrentTimestamp();
    
    if (type == HEARTBEAT) {
        doc["message_type"] = "heartbeat";
        
        // Add status information
        JsonObject status = doc.createNestedObject("data");
        status["status"] = "online";
        status["uptime"] = getUptimeSeconds();
        status["wifi_rssi"] = getWiFiRSSI();
        status["free_memory"] = ESP.getFreeHeap();
        
    } else if (type == ALERT) {
        doc["message_type"] = "alert";

        // Add detection information with sensor data
        JsonObject detection = doc.createNestedObject("data");
        detection["event"] = "ultrasonic_detection";
        detection["sensor_type"] = "HC-SR04";
        detection["detected_distance_cm"] = distance;
        detection["detection_duration_seconds"] = durationSeconds;
        detection["first_detected_at"] = firstDetectedTimestamp;
        detection["confidence"] = 1.0;
    }
    
    // Serialize to string
    String payload;
    serializeJson(doc, payload);
    
    return payload;
}

/**
 * @brief Handle successful HTTP response (2xx status codes)
 * @param httpCode HTTP response code
 * @return true if successful (2xx), false otherwise
 */
static bool handleHTTPSuccess(int httpCode) {
    if (httpCode == 200 || httpCode == 201) {
        Serial.println("\n[MSG] SUCCESS - Message accepted by server");
        showSuccessPattern();
        return true;
    }
    return false;
}


/**
 * @brief Handle HTTP client errors (4xx status codes)
 * @param httpCode HTTP response code
 */
static void handleHTTPClientError(int httpCode) {
    if (httpCode == 400) {
        Serial.println("\n[MSG] BAD REQUEST (400)");
        Serial.println("[MSG] Possible causes:");
        Serial.println("[MSG]   - Invalid JSON payload");
        Serial.println("[MSG]   - Missing required fields");
        showErrorPattern(3);

    } else if (httpCode == 401 || httpCode == 403) {
        Serial.println("\n[MSG] AUTHENTICATION FAILED (401/403)");
        Serial.println("[MSG] Possible causes:");
        Serial.println("[MSG]   - Invalid certificate");
        Serial.println("[MSG]   - Invalid signature");
        Serial.println("[MSG]   - Certificate expired or revoked");
        showErrorPattern(4);

    } else {
        Serial.print("\n[MSG] CLIENT ERROR: ");
        Serial.println(httpCode);
        showErrorPattern(6);
    }
}


/**
 * @brief Handle HTTP server errors (5xx status codes)
 * @param httpCode HTTP response code
 */
static void handleHTTPServerError(int httpCode) {
    Serial.println("\n[MSG] SERVER ERROR (5xx)");
    Serial.println("[MSG] The C3DS server encountered an error");
    showErrorPattern(5);
}


/**
 * @brief Handle network-level errors (negative error codes)
 * @param errorCode HTTP client error code
 */
static void handleNetworkError(int errorCode) {
    Serial.println("[MSG] HTTP REQUEST FAILED");
    Serial.print("[MSG] Error code: ");
    Serial.println(errorCode);

    // Common ESP8266 HTTP error codes
    switch (errorCode) {
        case -1:
            Serial.println("[MSG] Connection failed - Cannot reach server");
            Serial.println("[MSG] Check:");
            Serial.println("[MSG]   - Server is running");
            Serial.println("[MSG]   - SERVER_URL is correct");
            Serial.println("[MSG]   - Device and server on same network");
            break;
        case -2:
            Serial.println("[MSG] Send header failed");
            break;
        case -3:
            Serial.println("[MSG] Send payload failed");
            break;
        case -4:
            Serial.println("[MSG] Not connected");
            break;
        case -5:
            Serial.println("[MSG] Connection lost");
            break;
        case -11:
            Serial.println("[MSG] Read timeout");
            break;
        default:
            Serial.println("[MSG] Unknown error");
            break;
    }

    showErrorPattern(10);
}


/**
 * @brief POST an acknowledgement for a delivered command to ACK_URL.
 *
 * Uses the same certificate + ECDSA-P256 signing as the main message endpoint.
 * Fire-and-forget: failure is logged but does not block the main loop.
 *
 * @param commandId UUID string of the command being acknowledged
 * @param ackStatus "ok" or "error"
 * @param detail    Human-readable detail string (may be empty)
 */
static void sendAck(const char* commandId, const char* ackStatus, const char* detail) {
    // Build the JSON body
    StaticJsonDocument<256> doc;
    doc["command_id"] = commandId;
    doc["status"]     = ackStatus;
    doc["detail"]     = detail;
    String body;
    serializeJson(doc, body);

    // Sign the body
    String sig = signMessage(body);
    if (sig.length() == 0) {
        Serial.println("[CMD] Failed to sign ack — skipping");
        return;
    }

    WiFiClient client;
    HTTPClient http;
    if (!http.begin(client, ACK_URL)) {
        Serial.println("[CMD] Failed to begin ack HTTP connection");
        return;
    }
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Device-Certificate", DEVICE_CERTIFICATE_B64);
    http.addHeader("X-Device-Signature", sig);
    http.setTimeout(HTTP_TIMEOUT);

    int code = http.POST(body);
    if (code > 0) {
        Serial.printf("[CMD] Ack sent — HTTP %d\n", code);
    } else {
        Serial.printf("[CMD] Ack failed — error %d\n", code);
    }
    http.end();
}


/**
 * @brief Parse the `commands` array from a server response and execute each command.
 *
 * Supported commands:
 *   SET_INTERVAL  {"seconds": N}  — changes heartbeatIntervalMs
 *   SET_THRESHOLD {"cm": N}       — changes detectionThresholdCm
 *   REBOOT        {}              — calls ESP.restart() after sending ack
 *
 * Each executed command is acknowledged via sendAck().
 *
 * @param responseBody Raw JSON string returned by the server
 */
static void processServerCommands(const String& responseBody) {
    StaticJsonDocument<1024> doc;
    DeserializationError err = deserializeJson(doc, responseBody);
    if (err != DeserializationError::Ok) {
        Serial.println("[CMD] Failed to parse response JSON");
        return;
    }

    JsonArray commands = doc["commands"].as<JsonArray>();
    if (commands.isNull() || commands.size() == 0) {
        return;  // No commands — normal case
    }

    Serial.printf("[CMD] %u command(s) received\n", (unsigned)commands.size());

    for (JsonObject cmd : commands) {
        const char* action = cmd["action"] | "";
        const char* id     = cmd["id"]     | "";

        Serial.printf("[CMD] Executing: %s (id=%s)\n", action, id);

        if (strcmp(action, "SET_INTERVAL") == 0) {
            unsigned long seconds = cmd["params"]["seconds"] | 0UL;
            if (seconds > 0) {
                heartbeatIntervalMs = seconds * 1000UL;
                Serial.printf("[CMD] SET_INTERVAL -> %lu s\n", seconds);
                sendAck(id, "ok", "heartbeat interval updated");
            } else {
                Serial.println("[CMD] SET_INTERVAL: invalid seconds value");
                sendAck(id, "error", "invalid seconds value");
            }

        } else if (strcmp(action, "SET_THRESHOLD") == 0) {
            float cm = cmd["params"]["cm"] | 0.0f;
            if (cm > 0.0f) {
                detectionThresholdCm = cm;
                Serial.printf("[CMD] SET_THRESHOLD -> %.1f cm\n", cm);
                sendAck(id, "ok", "detection threshold updated");
            } else {
                Serial.println("[CMD] SET_THRESHOLD: invalid cm value");
                sendAck(id, "error", "invalid cm value");
            }

        } else if (strcmp(action, "REBOOT") == 0) {
            Serial.println("[CMD] REBOOT — sending ack then restarting");
            sendAck(id, "ok", "rebooting");
            delay(500);
            ESP.restart();

        } else {
            Serial.printf("[CMD] Unknown action: %s\n", action);
            sendAck(id, "error", "unknown action");
        }
    }
}


/**
 * Send HTTP POST request with signed message
 *
 * @param payload JSON message payload
 * @param signature ECDSA signature of the payload
 * @return true if request successful (HTTP 200/201), false otherwise
 */
static bool sendHTTPRequest(const String& payload, const String& signature) {
    WiFiClient client;
    HTTPClient http;
    
    Serial.println("\n[MSG] ═══════════════════════════════════");
    Serial.println("[MSG] Sending HTTP Request");
    Serial.println("[MSG] ═══════════════════════════════════");
    
    // Begin HTTP connection
    Serial.print("[MSG] URL: ");
    Serial.println(SERVER_URL);
    
    if (!http.begin(client, SERVER_URL)) {
        Serial.println("[MSG] Failed to begin HTTP connection");
        return false;
    }
    
    // Set request headers
    http.addHeader("Content-Type", "application/json");
    http.addHeader("X-Device-Certificate", DEVICE_CERTIFICATE_B64);
    http.addHeader("X-Device-Signature", signature);
    
    Serial.println("[MSG] Headers:");
    Serial.println("[MSG]   Content-Type: application/json");
    Serial.print("[MSG]   X-Device-Certificate: ");
    Serial.print(String(DEVICE_CERTIFICATE_B64).substring(0, 50));
    Serial.println("...");
    Serial.print("[MSG]   X-Device-Signature: ");
    Serial.println(signature);
    
    // Set timeout
    http.setTimeout(HTTP_TIMEOUT);
    
    // Send POST request
    Serial.println("\n[MSG] Payload:");
    Serial.println(payload);
    Serial.println();
    
    int httpResponseCode = http.POST(payload);
    
    // Process response
    Serial.println("[MSG] ───────────────────────────────────");
    Serial.println("[MSG] Server Response");
    Serial.println("[MSG] ───────────────────────────────────");
    
    bool success = false;

    if (httpResponseCode > 0) {
        Serial.print("[MSG] HTTP Response Code: ");
        Serial.println(httpResponseCode);

        // Get response body
        String response = http.getString();
        Serial.println("[MSG] Response Body:");
        Serial.println(response);

        // Handle response based on status code category
        if (httpResponseCode >= 200 && httpResponseCode < 300) {
            success = handleHTTPSuccess(httpResponseCode);
            processServerCommands(response);
        } else if (httpResponseCode >= 400 && httpResponseCode < 500) {
            handleHTTPClientError(httpResponseCode);
        } else if (httpResponseCode >= 500) {
            handleHTTPServerError(httpResponseCode);
        } else {
            Serial.print("\n[MSG] UNEXPECTED RESPONSE: ");
            Serial.println(httpResponseCode);
            showErrorPattern(6);
        }

    } else {
        // Request failed - network error
        handleNetworkError(httpResponseCode);
    }
    
    // Clean up
    http.end();
    Serial.println("[MSG] ═══════════════════════════════════\n");
    
    return success;
}

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

bool initializeMessaging() {
    Serial.println("\n[MSG] Initializing messaging subsystem...");
    
    if (!isCryptoReady()) {
        Serial.println("[MSG] Crypto not ready!");
        messagingReady = false;
        return false;
    }
    
    if (!isTimeInitialized()) {
        Serial.println("[MSG] Time not synchronized!");
        messagingReady = false;
        return false;
    }
    
    Serial.println("[MSG] Messaging subsystem ready");
    messagingReady = true;
    lastHeartbeatTime = millis();
    
    return true;
}

bool sendHeartbeat() {
    if (!messagingReady) {
        Serial.println("[MSG] Messaging not initialized!");
        return false;
    }
    
    if (!isWiFiConnected()) {
        Serial.println("[MSG] WiFi not connected!");
        return false;
    }
    
    Serial.println("\n[MSG] ╔═══════════════════════════════════╗");
    Serial.println("[MSG] ║      HEARTBEAT MESSAGE            ║");
    Serial.println("[MSG] ╚═══════════════════════════════════╝");
    
    // Create message payload
    String payload = createMessagePayload(HEARTBEAT);
    
    // Sign the payload
    String signature = signMessage(payload);
    
    if (signature.length() == 0) {
        Serial.println("[MSG] Failed to sign message!");
        return false;
    }
    
    // Send HTTP request
    bool success = sendHTTPRequest(payload, signature);

    // Always update lastHeartbeatTime to prevent rapid retries on failure
    lastHeartbeatTime = millis();

    return success;
}

bool sendAlert(float distance, unsigned long durationSeconds, const String& firstDetectedTimestamp) {
    if (!messagingReady) {
        Serial.println("[MSG] Messaging not initialized!");
        return false;
    }

    if (!isWiFiConnected()) {
        Serial.println("[MSG] WiFi not connected!");
        return false;
    }

    Serial.println("\n[MSG] ╔═══════════════════════════════════╗");
    Serial.println("[MSG] ║       ALERT MESSAGE               ║");
    Serial.println("[MSG] ╚═══════════════════════════════════╝");
    Serial.print("[MSG] Distance: ");
    Serial.print(distance, 1);
    Serial.println(" cm");
    Serial.print("[MSG] Duration: ");
    Serial.print(durationSeconds);
    Serial.println(" seconds");
    Serial.print("[MSG] First detected: ");
    Serial.println(firstDetectedTimestamp);

    // Create message payload with sensor data
    String payload = createMessagePayload(ALERT, distance, durationSeconds, firstDetectedTimestamp);

    // Sign the payload
    String signature = signMessage(payload);

    if (signature.length() == 0) {
        Serial.println("[MSG] Failed to sign message!");
        return false;
    }

    // Send HTTP request
    bool success = sendHTTPRequest(payload, signature);

    return success;
}

bool isHeartbeatDue() {
    return (millis() - lastHeartbeatTime) >= heartbeatIntervalMs;
}

unsigned long getHeartbeatInterval() {
    return heartbeatIntervalMs;
}

float getDetectionThreshold() {
    return detectionThresholdCm;
}

unsigned long getLastHeartbeatTime() {
    return lastHeartbeatTime;
}