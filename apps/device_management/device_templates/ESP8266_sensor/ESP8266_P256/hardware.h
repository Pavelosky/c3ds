#ifndef HARDWARE_H
#define HARDWARE_H

#include <Arduino.h>
#include "config.h"

// ============================================================================
// HARDWARE ABSTRACTION LAYER
// ============================================================================
// This module handles all physical hardware interactions:
// - HC-SR04 ultrasonic sensor for object detection
// - LED status indicators
// - Hardware initialization
// ============================================================================

// Initialize all hardware components (pins, sensors)
void initializeHardware();

/**
 * Check if sensor should be polled (based on polling interval)
 * @return true if it's time to read sensor, false otherwise
 */
bool isSensorPollDue();

/**
 * Read distance from HC-SR04 sensor and update detection state
 * This function handles:
 * - Distance measurement
 * - Consecutive reading validation
 * - Hysteresis logic
 * - Detection state tracking
 *
 * @return true if sensor was polled (regardless of detection state)
 */
bool pollSensor();

/**
 * Check if object is currently detected (within threshold)
 * @return true if object detected, false otherwise
 */
bool isObjectDetected();

/**
 * Check if alert should be sent (10 second interval while detecting)
 * @return true if alert is due, false otherwise
 */
bool isAlertDue();

/**
 * Get the current detected distance in centimeters
 * @return Distance in cm (0 if no valid reading or not detecting)
 */
float getDetectedDistance();

/**
 * Get how long object has been detected (in seconds)
 * @return Duration in seconds since first detection
 */
unsigned long getDetectionDuration();

/**
 * Get ISO timestamp of when object was first detected
 * @return ISO 8601 formatted timestamp string
 */
String getFirstDetectionTimestamp();

/**
 * Mark that an alert was just sent
 * Updates internal timer for next alert interval
 */
void markAlertSent();

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

/**
 * Update LED blink pattern while object is detected
 * Call this regularly in loop() to maintain continuous blinking
 */
void updateDetectionLED();

#endif // HARDWARE_H
