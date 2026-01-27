#include "config.h"
#include "hardware.h"
#include "network.h"  // For getCurrentTimestamp()

// ============================================================================
// INTERNAL STATE VARIABLES
// ============================================================================

// Sensor polling timing
static unsigned long lastSensorPoll = 0;

// Distance measurement
static float currentDistance = 0.0;
static float previousDistance = 0.0;
static int consecutiveValidReadings = 0;

// Detection state tracking
static bool detectionActive = false;
static unsigned long firstDetectionTime = 0;      // millis() when first detected
static String firstDetectionTimestamp = "";       // ISO timestamp when first detected
static unsigned long lastAlertTime = 0;           // millis() when last alert sent

// LED blinking for detection
static unsigned long lastLEDToggle = 0;
static bool ledState = false;
static const unsigned long LED_BLINK_INTERVAL = 300;  // 300ms on/off for continuous blink

// ============================================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================================

/**
 * Measure distance using HC-SR04 ultrasonic sensor
 *
 * @return Distance in centimeters, or -1 if measurement failed
 */
static float measureDistance() {
    // Send 10us pulse to trigger pin
    digitalWrite(SENSOR_TRIG_PIN, LOW);
    delayMicroseconds(2);
    digitalWrite(SENSOR_TRIG_PIN, HIGH);
    delayMicroseconds(10);
    digitalWrite(SENSOR_TRIG_PIN, LOW);

    // Read echo pulse duration (timeout configured in config.h)
    unsigned long duration = pulseIn(SENSOR_ECHO_PIN, HIGH, SENSOR_PULSE_TIMEOUT_MICROSECONDS);

    // Check for timeout or invalid reading
    if (duration == 0) {
        return -1.0;  // No echo received
    }

    // Calculate distance in cm
    // Speed of sound constant defined in config.h (343 m/s = 0.0343 cm/μs at 20°C)
    // Distance = (duration / 2) * speed_of_sound
    float distance = (duration / 2.0) * SPEED_OF_SOUND_CM_PER_MICROSECOND;

    // Validate range (constants defined in config.h)
    if (distance < SENSOR_MIN_DISTANCE_CM || distance > SENSOR_MAX_DISTANCE_CM) {
        return -1.0;  // Out of reliable range
    }

    return distance;
}

/**
 * Check if distance reading indicates object detected (with hysteresis)
 *
 * @param distance Current distance measurement in cm
 * @return true if object detected, false otherwise
 */
static bool isDistanceInDetectionRange(float distance) {
    if (detectionActive) {
        // Currently detecting - use upper threshold (hysteresis)
        return distance <= (DETECTION_THRESHOLD_CM + DETECTION_HYSTERESIS_CM);
    } else {
        // Not detecting - use lower threshold
        return distance <= DETECTION_THRESHOLD_CM;
    }
}

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

void initializeHardware() {
    // Configure HC-SR04 pins
    pinMode(SENSOR_TRIG_PIN, OUTPUT);
    pinMode(SENSOR_ECHO_PIN, INPUT);
    digitalWrite(SENSOR_TRIG_PIN, LOW);

    // Configure LED pins as outputs
    pinMode(STATUS_LED_PIN, OUTPUT);
    pinMode(BUILTIN_LED_PIN, OUTPUT);

    // Initialize LEDs to OFF state
    digitalWrite(STATUS_LED_PIN, LOW);      // Status LED off
    digitalWrite(BUILTIN_LED_PIN, HIGH);    // Built-in LED off (inverted logic)

    Serial.println("[HW] Hardware initialized");
    Serial.print("[HW] HC-SR04 Trigger pin: D");
    Serial.println(SENSOR_TRIG_PIN);
    Serial.print("[HW] HC-SR04 Echo pin: D");
    Serial.println(SENSOR_ECHO_PIN);
    Serial.print("[HW] Status LED pin: D");
    Serial.println(STATUS_LED_PIN);
    Serial.print("[HW] Built-in LED pin: D");
    Serial.println(BUILTIN_LED_PIN);
    Serial.print("[HW] Detection threshold: ");
    Serial.print(DETECTION_THRESHOLD_CM);
    Serial.println(" cm");
    Serial.print("[HW] Detection hysteresis: ");
    Serial.print(DETECTION_HYSTERESIS_CM);
    Serial.println(" cm");
}

bool isSensorPollDue() {
    return (millis() - lastSensorPoll) >= SENSOR_POLL_INTERVAL;
}


/**
 * @brief Handle transition from IDLE to DETECTING state
 * @param distance Current distance measurement in cm
 */
static void transitionToDetecting(float distance) {
    detectionActive = true;
    firstDetectionTime = millis();
    firstDetectionTimestamp = getCurrentTimestamp();
    lastAlertTime = 0;  // Force immediate alert
    consecutiveValidReadings = 0;

    Serial.println("\n[HW] ═══════════════════════════════════");
    Serial.println("[HW] OBJECT DETECTED!");
    Serial.print("[HW] Distance: ");
    Serial.print(distance, 1);
    Serial.println(" cm");
    Serial.print("[HW] First detected at: ");
    Serial.println(firstDetectionTimestamp);
    Serial.println("[HW] ═══════════════════════════════════\n");
}


/**
 * @brief Handle transition from DETECTING to IDLE state
 */
static void transitionToIdle() {
    detectionActive = false;
    unsigned long detectionDuration = (millis() - firstDetectionTime) / 1000;

    Serial.println("\n[HW] ───────────────────────────────────");
    Serial.println("[HW] OBJECT LEFT DETECTION ZONE");
    Serial.print("[HW] Detection duration: ");
    Serial.print(detectionDuration);
    Serial.println(" seconds");
    Serial.println("[HW] ───────────────────────────────────\n");

    // Turn off LED
    setStatusLED(false);
}


/**
 * @brief Update detection state machine based on current sensor reading
 * @param distance Current distance measurement in cm
 * @param readingInRange Whether the reading is within detection threshold
 */
static void updateDetectionStateMachine(float distance, bool readingInRange) {
    static int consecutiveOutOfRange = 0;

    // ────────────────────────────────────────────────────────────────────────
    // State Machine: IDLE → DETECTING
    // ────────────────────────────────────────────────────────────────────────
    if (!detectionActive && consecutiveValidReadings >= CONSECUTIVE_READINGS_REQUIRED) {
        transitionToDetecting(distance);
        return;
    }

    // ────────────────────────────────────────────────────────────────────────
    // State Machine: DETECTING → IDLE
    // ────────────────────────────────────────────────────────────────────────
    if (detectionActive && !readingInRange && consecutiveValidReadings == 0) {
        // Need consecutive readings to confirm object is gone
        consecutiveOutOfRange++;

        if (consecutiveOutOfRange >= CONSECUTIVE_READINGS_REQUIRED) {
            transitionToIdle();
            consecutiveOutOfRange = 0;
        }
    } else {
        // Reset out-of-range counter
        consecutiveOutOfRange = 0;
    }
}


bool pollSensor() {
    // Update poll timestamp
    lastSensorPoll = millis();

    // Measure distance
    float distance = measureDistance();

    // Check if reading is valid
    if (distance < 0) {
        Serial.println("[HW] Invalid sensor reading (timeout or out of range)");
        consecutiveValidReadings = 0;
        return true;  // Sensor was polled (even though reading failed)
    }

    // Valid reading obtained
    previousDistance = currentDistance;
    currentDistance = distance;

    // Check if reading is within detection range
    bool readingInRange = isDistanceInDetectionRange(distance);

    // Debug output
    Serial.print("[HW] Distance: ");
    Serial.print(distance, 1);
    Serial.print(" cm | Detection: ");
    Serial.print(detectionActive ? "ACTIVE" : "IDLE");
    Serial.print(" | Valid readings: ");
    Serial.println(consecutiveValidReadings);

    // Update consecutive readings counter
    if (readingInRange) {
        consecutiveValidReadings++;
    } else {
        consecutiveValidReadings = 0;
    }

    // Update detection state machine based on readings
    updateDetectionStateMachine(distance, readingInRange);

    return true;
}

bool isObjectDetected() {
    return detectionActive;
}

bool isAlertDue() {
    if (!detectionActive) {
        return false;  // No alert if not detecting
    }

    // Check if enough time has passed since last alert
    unsigned long timeSinceLastAlert = millis() - lastAlertTime;
    return timeSinceLastAlert >= ALERT_INTERVAL;
}

float getDetectedDistance() {
    if (!detectionActive) {
        return 0.0;  // No detection = no distance
    }
    return currentDistance;
}

unsigned long getDetectionDuration() {
    if (!detectionActive) {
        return 0;  // Not detecting
    }

    return (millis() - firstDetectionTime) / 1000;  // Convert ms to seconds
}

String getFirstDetectionTimestamp() {
    return firstDetectionTimestamp;
}

void markAlertSent() {
    lastAlertTime = millis();
    Serial.println("[HW] Alert sent marker updated");
}

void blinkStatusLED(int times, unsigned long duration_ms) {
    for (int i = 0; i < times; i++) {
        digitalWrite(STATUS_LED_PIN, HIGH);
        delay(duration_ms);
        digitalWrite(STATUS_LED_PIN, LOW);

        // Add gap between blinks (except after last blink)
        if (i < times - 1) {
            delay(duration_ms);
        }
    }
}

void setStatusLED(bool state) {
    digitalWrite(STATUS_LED_PIN, state ? HIGH : LOW);
    ledState = state;
}

void setWiFiLED(bool state) {
    // Built-in LED has inverted logic: LOW = on, HIGH = off
    digitalWrite(BUILTIN_LED_PIN, state ? LOW : HIGH);
}

void showSuccessPattern() {
    // 1 long blink = success
    blinkStatusLED(1, 1000);
}

void showErrorPattern(int errorCode) {
    // Multiple rapid blinks indicate error
    // Number of blinks indicates error type
    blinkStatusLED(errorCode, 200);
    delay(500);  // Pause after error pattern
}

void updateDetectionLED() {
    if (!detectionActive) {
        // Not detecting - ensure LED is off
        if (ledState) {
            setStatusLED(false);
        }
        return;
    }

    // Detecting - blink continuously
    unsigned long now = millis();
    if (now - lastLEDToggle >= LED_BLINK_INTERVAL) {
        ledState = !ledState;
        digitalWrite(STATUS_LED_PIN, ledState ? HIGH : LOW);
        lastLEDToggle = now;
    }
}
