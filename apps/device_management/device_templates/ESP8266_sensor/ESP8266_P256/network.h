#ifndef NETWORK_H
#define NETWORK_H

#include <Arduino.h>
#include "config.h"

// ============================================================================
// NETWORK MANAGEMENT MODULE
// ============================================================================
// This module handles:
// - WiFi connection and reconnection
// - NTP time synchronization
// - Network status monitoring
// ============================================================================

/**
 * Initialize WiFi connection
 * Connects to WiFi network specified in config.h
 * Blocks until connection is established or timeout occurs
 * 
 * @return true if connected successfully, false on timeout
 */
bool initializeWiFi();

/**
 * Check if WiFi is connected
 * 
 * @return true if connected, false otherwise
 */
bool isWiFiConnected();

/**
 * Reconnect to WiFi if connection was lost
 * Non-blocking - returns immediately
 * 
 * @return true if reconnection successful, false otherwise
 */
bool reconnectWiFi();

/**
 * Initialize NTP (Network Time Protocol) time synchronization
 * Gets current time from internet time servers
 * Must be called after WiFi is connected
 * 
 * @return true if time synchronized successfully, false otherwise
 */
bool initializeNTP();

/**
 * Check if time has been synchronized with NTP server
 * 
 * @return true if time is valid, false otherwise
 */
bool isTimeInitialized();

/**
 * Get current timestamp in ISO 8601 format (UTC)
 * Format: "2025-01-18T14:30:45Z"
 * 
 * @return String containing formatted timestamp
 */
String getCurrentTimestamp();

/**
 * Get WiFi signal strength (RSSI)
 * 
 * @return Signal strength in dBm (e.g., -65)
 */
int getWiFiRSSI();

/**
 * Get device uptime in seconds
 * 
 * @return Uptime in seconds
 */
unsigned long getUptimeSeconds();

/**
 * Print network diagnostics to serial monitor
 * Useful for debugging connection issues
 */
void printNetworkDiagnostics();

#endif // NETWORK_H