// ============================================================================
// C3DS - Civilian Distributed Drone Detection System
// ESP8266 IoT Sensor Node
// ============================================================================
// 
// Academic Project: BSc Computer Science Final Year Project
// Project: Physical Computing and the Internet of Things
// Focus: Secure IoT Device Management in Safety-critical Smart Environment
//
// This firmware implements a secure IoT sensor that:
// - Sends heartbeat messages every 20 seconds (when idle, automatic status updates)
// - Sends alert messages when HC-SR04 sensor detects object within 25cm (every 10s while detecting)
// - Heartbeats are skipped during active detection (alerts provide status info)
// - Signs all messages with ECDSA P-256 cryptographic signatures
// - Communicates with Django backend via HTTP REST API
//
// Hardware: ESP8266 (NodeMCU / Wemos D1 Mini)
// Security: ECDSA P-256, X.509 certificates, signed messages
//
// ============================================================================

#include "config.h"
#include "hardware.h"
#include "network.h"
#include "crypto.h"
#include "messaging.h"

// ============================================================================
// GLOBAL STATE
// ============================================================================

bool systemReady = false;

// ============================================================================
// SETUP - Runs once at boot
// ============================================================================

void setup() {
    // Initialize serial communication for debugging
    Serial.begin(115200);
    delay(100);  // Allow serial to stabilize
    
    Serial.println("\n\n");
    Serial.println("╔════════════════════════════════════════════════════════════╗");
    Serial.println("║                                                            ║");
    Serial.println("║              C3DS - IoT Sensor Node v1.0                   ║");
    Serial.println("║     Civilian Distributed Drone Detection System            ║");
    Serial.println("║                                                            ║");
    Serial.println("╚════════════════════════════════════════════════════════════╝");
    Serial.println();
    Serial.print("Device ID: ");
    Serial.println(DEVICE_ID);
    Serial.print("Firmware: ESP8266 C3DS Sensor v1.0");
    Serial.println();
    Serial.println("Starting initialization sequence...\n");
    
    // ────────────────────────────────────────────────────────────────────────
    // STEP 1: Initialize Hardware
    // ────────────────────────────────────────────────────────────────────────
    Serial.println("════════════════════════════════════════════════════════════");
    Serial.println("STEP 1/5: Hardware Initialization");
    Serial.println("════════════════════════════════════════════════════════════");
    
    initializeHardware();
    
    // Visual indication: blink both LEDs
    setStatusLED(true);
    setWiFiLED(true);
    delay(500);
    setStatusLED(false);
    setWiFiLED(false);
    delay(500);
    
    Serial.println("Hardware initialization complete\n");
    
    // ────────────────────────────────────────────────────────────────────────
    // STEP 2: Connect to WiFi
    // ────────────────────────────────────────────────────────────────────────
    Serial.println("════════════════════════════════════════════════════════════");
    Serial.println("STEP 2/5: Network Connection");
    Serial.println("════════════════════════════════════════════════════════════");
    
    if (!initializeWiFi()) {
        Serial.println("\nFATAL ERROR: WiFi connection failed!");
        Serial.println("System halted. Please check configuration and reset device.");
        
        // Indicate error with rapid LED blinking
        while (true) {
            blinkStatusLED(10, 100);
            delay(2000);
        }
    }
    
    Serial.println("Network connection complete\n");
    
    // ────────────────────────────────────────────────────────────────────────
    // STEP 3: Synchronize Time (NTP)
    // ────────────────────────────────────────────────────────────────────────
    Serial.println("════════════════════════════════════════════════════════════");
    Serial.println("STEP 3/5: Time Synchronization");
    Serial.println("════════════════════════════════════════════════════════════");
    
    if (!initializeNTP()) {
        Serial.println("\nFATAL ERROR: Time synchronization failed!");
        Serial.println("System halted. Please check NTP server and reset device.");
        
        while (true) {
            blinkStatusLED(8, 100);
            delay(2000);
        }
    }
    
    Serial.println("Time synchronization complete\n");
    
    // ────────────────────────────────────────────────────────────────────────
    // STEP 4: Initialize Cryptography
    // ────────────────────────────────────────────────────────────────────────
    Serial.println("════════════════════════════════════════════════════════════");
    Serial.println("STEP 4/5: Cryptographic Initialization");
    Serial.println("════════════════════════════════════════════════════════════");
    
    if (!initializeCrypto()) {
        Serial.println("\nFATAL ERROR: Cryptography initialization failed!");
        Serial.println("System halted. Please check private key and reset device.");
        
        while (true) {
            blinkStatusLED(6, 100);
            delay(2000);
        }
    }
    
    Serial.println("Cryptographic initialization complete\n");
    
    // ────────────────────────────────────────────────────────────────────────
    // STEP 5: Initialize Messaging
    // ────────────────────────────────────────────────────────────────────────
    Serial.println("════════════════════════════════════════════════════════════");
    Serial.println("STEP 5/5: Messaging Subsystem");
    Serial.println("════════════════════════════════════════════════════════════");
    
    if (!initializeMessaging()) {
        Serial.println("\nFATAL ERROR: Messaging initialization failed!");
        Serial.println("System halted. Please reset device.");
        
        while (true) {
            blinkStatusLED(4, 100);
            delay(2000);
        }
    }
    
    Serial.println("Messaging subsystem complete\n");
    
    // ────────────────────────────────────────────────────────────────────────
    // Initialization Complete
    // ────────────────────────────────────────────────────────────────────────
    Serial.println("════════════════════════════════════════════════════════════");
    Serial.println("ALL SYSTEMS OPERATIONAL");
    Serial.println("════════════════════════════════════════════════════════════");
    Serial.println();
    
    printNetworkDiagnostics();
    
    Serial.println("╔════════════════════════════════════════════════════════════╗");
    Serial.println("║                    DEVICE READY                            ║");
    Serial.println("╚════════════════════════════════════════════════════════════╝");
    Serial.println();
    Serial.println("Operational modes:");
    Serial.println("  → Heartbeat: Every 20 seconds (when idle)");
    Serial.println("  → Alert: Object detected within 25cm (HC-SR04 sensor)");
    Serial.println("  → Sensor polling: Every 500ms");
    Serial.println("  → Alert interval: Every 10 seconds while detecting");
    Serial.println("  → Note: Heartbeats skipped during active detection");
    Serial.println();
    Serial.println("Waiting for events...\n");
    
    systemReady = true;
    
    // Success indication: 3 short blinks
    blinkStatusLED(3, 200);
    
    // Send initial heartbeat to announce device is online
    Serial.println("[MAIN] Sending initial heartbeat...");
    sendHeartbeat();
}

// ============================================================================
// LOOP - Runs continuously
// ============================================================================

void loop() {
    // Only run if system is ready
    if (!systemReady) {
        delay(1000);
        return;
    }
    
    // ────────────────────────────────────────────────────────────────────────
    // Check WiFi Connection
    // ────────────────────────────────────────────────────────────────────────
    if (!isWiFiConnected()) {
        Serial.println("\n[MAIN] WiFi disconnected! Attempting reconnection...");
        setWiFiLED(false);
        
        if (reconnectWiFi()) {
            Serial.println("[MAIN] WiFi reconnected successfully");
            
            // Re-sync time after reconnection
            if (!initializeNTP()) {
                Serial.println("[MAIN] Warning: Time re-sync failed");
            }
        } else {
            Serial.println("[MAIN] WiFi reconnection failed, will retry...");
            delay(5000);  // Wait before next attempt
            return;
        }
    }
    
    // ────────────────────────────────────────────────────────────────────────
    // Poll HC-SR04 Sensor (Check for Object Detection)
    // ────────────────────────────────────────────────────────────────────────
    if (isSensorPollDue()) {
        pollSensor();  // Updates detection state internally
    }

    // ────────────────────────────────────────────────────────────────────────
    // Update LED Blinking Pattern (Continuous blink while detecting)
    // ────────────────────────────────────────────────────────────────────────
    updateDetectionLED();

    // ────────────────────────────────────────────────────────────────────────
    // Send Alert Message (If Object Detected and Alert Interval Reached)
    // ────────────────────────────────────────────────────────────────────────
    if (isObjectDetected() && isAlertDue()) {
        Serial.println("[MAIN] Alert triggered by object detection!");

        // Get sensor data
        float distance = getDetectedDistance();
        unsigned long duration = getDetectionDuration();
        String timestamp = getFirstDetectionTimestamp();

        // Send alert message with sensor data
        if (sendAlert(distance, duration, timestamp)) {
            Serial.println("[MAIN] Alert message sent successfully");
            markAlertSent();  // Update timer for next alert
        } else {
            Serial.println("[MAIN] Alert message failed");
        }
    }
    
    // ────────────────────────────────────────────────────────────────────────
    // Check if Heartbeat is Due (Automatic Status Update)
    // ────────────────────────────────────────────────────────────────────────
    // Note: Skip heartbeat when actively detecting - alerts contain all status info
    if (isHeartbeatDue() && !isObjectDetected()) {
        Serial.println("[MAIN] Heartbeat interval reached");

        // Send heartbeat message
        if (sendHeartbeat()) {
            Serial.println("[MAIN] Heartbeat sent successfully");
        } else {
            Serial.println("[MAIN] Heartbeat failed");
        }
    }
    
    // Small delay to prevent CPU hogging
    delay(10);
}