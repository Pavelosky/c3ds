#ifndef MESSAGING_H
#define MESSAGING_H

#include <Arduino.h>
#include "config.h"

// ============================================================================
// MESSAGING MODULE
// ============================================================================
// This module handles:
// - Creating heartbeat and alert messages
// - Signing messages with ECDSA
// - Sending messages to Django API
// - Processing server responses
// ============================================================================

/**
 * Message types
 */
enum MessageType {
    HEARTBEAT,  // Automatic status update every 20 seconds
    ALERT       // Manual alert triggered by button press
};

/**
 * Initialize messaging subsystem
 * Call this once in setup()
 * 
 * @return true if initialization successful, false otherwise
 */
bool initializeMessaging();

/**
 * Send a heartbeat message to the server
 * Contains device status information
 * 
 * @return true if message sent successfully, false otherwise
 */
bool sendHeartbeat();

/**
 * Send an alert message to the server
 * Triggered by ultrasonic sensor - indicates object detection event
 *
 * @param distance Distance of detected object in cm
 * @param durationSeconds How long object has been detected (in seconds)
 * @param firstDetectedTimestamp ISO timestamp when object was first detected
 * @return true if message sent successfully, false otherwise
 */
bool sendAlert(float distance, unsigned long durationSeconds, const String& firstDetectedTimestamp);

/**
 * Check if it's time to send a heartbeat message
 * 
 * @return true if heartbeat is due, false otherwise
 */
bool isHeartbeatDue();

/**
 * Get the last heartbeat time
 *
 * @return Time in milliseconds when last heartbeat was sent
 */
unsigned long getLastHeartbeatTime();

/**
 * Get the current (runtime-configurable) heartbeat interval.
 * Updated by SET_INTERVAL commands from the server.
 *
 * @return Interval in milliseconds
 */
unsigned long getHeartbeatInterval();

/**
 * Get the current (runtime-configurable) detection threshold.
 * Updated by SET_THRESHOLD commands from the server.
 *
 * @return Distance threshold in centimetres
 */
float getDetectionThreshold();

#endif // MESSAGING_H