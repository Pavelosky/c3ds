#include "hardware.h"
#include "config.h"

// ============================================================================
// INTERNAL STATE VARIABLES
// ============================================================================

// Button debouncing state
static int lastButtonState = HIGH;      // Previous button reading
static int buttonState = HIGH;          // Current stable button state
static unsigned long lastDebounceTime = 0;    // Last time button changed
static unsigned long lastPressTime = 0;       // Last time button was pressed

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

void initializeHardware() {
    // Configure button pin as input with internal pull-up resistor
    // Pull-up means: button not pressed = HIGH, button pressed = LOW
    pinMode(BUTTON_PIN, INPUT_PULLUP);
    
    // Configure LED pins as outputs
    pinMode(STATUS_LED_PIN, OUTPUT);
    pinMode(BUILTIN_LED_PIN, OUTPUT);
    
    // Initialize LEDs to OFF state
    digitalWrite(STATUS_LED_PIN, LOW);      // Status LED off
    digitalWrite(BUILTIN_LED_PIN, HIGH);    // Built-in LED off (inverted logic)
    
    Serial.println("[HW] Hardware initialized");
    Serial.print("[HW] Button pin: D");
    Serial.println(BUTTON_PIN);
    Serial.print("[HW] Status LED pin: D");
    Serial.println(STATUS_LED_PIN);
    Serial.print("[HW] Built-in LED pin: D");
    Serial.println(BUILTIN_LED_PIN);
}

bool checkButtonPress() {
    // Read current button state
    int reading = digitalRead(BUTTON_PIN);
    
    // Check if button state changed (noise or actual press)
    if (reading != lastButtonState) {
        // Reset debounce timer
        lastDebounceTime = millis();
    }
    
    // Check if enough time has passed since last change (debounce)
    if ((millis() - lastDebounceTime) > DEBOUNCE_DELAY) {
        // State has been stable for debounce period
        
        // Check if button state actually changed
        if (reading != buttonState) {
            buttonState = reading;
            
            // Button was pressed (HIGH -> LOW transition due to pull-up)
            if (buttonState == LOW) {
                // Check minimum interval between presses
                unsigned long currentTime = millis();
                
                if (currentTime - lastPressTime >= MIN_PRESS_INTERVAL) {
                    lastPressTime = currentTime;
                    
                    Serial.println("\n[HW] ═══════════════════════════════════");
                    Serial.println("[HW] BUTTON PRESSED - ALERT TRIGGERED");
                    Serial.println("[HW] ═══════════════════════════════════\n");
                    
                    // Brief visual feedback
                    blinkStatusLED(1, 100);
                    
                    return true;
                } else {
                    Serial.println("[HW] Button press ignored (too soon)");
                }
            }
        }
    }
    
    // Save current reading for next iteration
    lastButtonState = reading;
    
    return false;
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