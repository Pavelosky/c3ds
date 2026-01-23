#ifndef HARDWARE_H
#define HARDWARE_H

#include <Arduino.h>

// ============================================================================
// HARDWARE ABSTRACTION LAYER
// ============================================================================
// This module handles all physical hardware interactions:
// - Button input with debouncing
// - LED status indicators
// - Hardware initialization
// ============================================================================

// Initialize all hardware components (pins, interrupts)
void initializeHardware();

/**
 * Check if button was pressed (with debouncing)
 * @return true if button was pressed, false otherwise
 */
bool checkButtonPress();

/**
 * Blink the status LED a specified number of times
 * @param times Number of blinks
 * @param duration_ms Duration of each blink in milliseconds
 */
void blinkStatusLED(int times, unsigned long duration_ms);

/**
 * Set status LED to on or off
 * 
 * @param state true = on, false = off
 */
void setStatusLED(bool state);

/**
 * Set WiFi indicator LED to on or off
 * @param state true = on, false = off
 */
void setWiFiLED(bool state);

/**
 * Show success pattern on status LED
 * 1 long blink = operation successful
 */
void showSuccessPattern();

/**
 * Show error pattern on status LED
 * Multiple rapid blinks = error
 * 
 * @param errorCode Number of blinks to show error type
 */
void showErrorPattern(int errorCode);

#endif // HARDWARE_H