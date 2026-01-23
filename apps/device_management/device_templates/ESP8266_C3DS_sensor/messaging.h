#ifndef MESSAGING_H
#define MESSAGING_H

#include <Arduino.h>

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
 * Triggered by button press - indicates detection event
 * 
 * @return true if message sent successfully, false otherwise
 */
bool sendAlert();

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

#endif // MESSAGING_H