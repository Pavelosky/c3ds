#ifndef CRYPTO_H
#define CRYPTO_H

#include <Arduino.h>
#include "config.h"

// ============================================================================
// CRYPTOGRAPHIC OPERATIONS MODULE
// ============================================================================
// This module handles:
// - ECDSA P-256 message signing
// - Base64 encoding of signatures
// - Cryptographic initialization
// ============================================================================

/**
 * Initialize cryptographic subsystem
 * Call this once in setup()
 * 
 * @return true if initialization successful, false otherwise
 */
bool initializeCrypto();

/**
 * Sign a message using ECDSA P-256
 * Creates a digital signature of the input message using the device's private key
 * 
 * @param message The message to sign (usually JSON payload)
 * @return Base64-encoded signature string, or empty string on failure
 */
String signMessage(const String& message);

/**
 * Encode binary data to Base64 string
 * Used for encoding signatures and certificates
 * 
 * @param data Pointer to binary data
 * @param length Length of binary data in bytes
 * @return Base64-encoded string
 */
String base64Encode(const uint8_t* data, size_t length);

/**
 * Get crypto module status
 * 
 * @return true if crypto module is ready, false otherwise
 */
bool isCryptoReady();

#endif // CRYPTO_H