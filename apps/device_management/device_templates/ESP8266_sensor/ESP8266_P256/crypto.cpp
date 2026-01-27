#include "config.h"
#include "crypto.h"
#include <uECC.h>

// BearSSL for SHA-256 hashing (ESP8266 built-in)
extern "C" {
    #include "bearssl/bearssl_hash.h"
}

// ============================================================================
// INTERNAL STATE VARIABLES
// ============================================================================

static bool cryptoReady = false;
static const struct uECC_Curve_t* curve = NULL;

// ============================================================================
// BASE64 ENCODING
// ============================================================================

static const char base64_chars[] = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ============================================================================
// DER ENCODING FOR ECDSA SIGNATURES
// ============================================================================

/**
 * Encode an ECDSA raw signature (r || s) to DER format.
 *
 * DER format for ECDSA signature:
 * SEQUENCE {
 *   INTEGER r,
 *   INTEGER s
 * }
 *
 * Note: Integers in DER are signed. If the high bit is set, a 0x00 prefix
 * is needed to indicate the number is positive.
 *
 * @param raw_sig Raw signature (64 bytes: r=32 bytes, s=32 bytes)
 * @param der_sig Output buffer for DER-encoded signature (max 72 bytes)
 * @return Length of DER-encoded signature
 */
static size_t encodeSignatureToDER(const uint8_t* raw_sig, uint8_t* der_sig) {
    const uint8_t* r = raw_sig;
    const uint8_t* s = raw_sig + 32;

    // Find where the actual value starts (skip leading zeros, but keep one if needed)
    int r_start = 0;
    while (r_start < 31 && r[r_start] == 0) r_start++;

    int s_start = 0;
    while (s_start < 31 && s[s_start] == 0) s_start++;

    // Calculate lengths
    int r_len = 32 - r_start;
    int s_len = 32 - s_start;

    // Check if we need padding (high bit set means negative in ASN.1)
    bool r_pad = (r[r_start] & 0x80) != 0;
    bool s_pad = (s[s_start] & 0x80) != 0;

    if (r_pad) r_len++;
    if (s_pad) s_len++;

    // Total length: 2 (INTEGER tag + len) + r_len + 2 (INTEGER tag + len) + s_len
    int inner_len = 2 + r_len + 2 + s_len;

    // Build DER encoding
    int idx = 0;

    // SEQUENCE header
    der_sig[idx++] = 0x30;  // SEQUENCE tag
    der_sig[idx++] = inner_len;

    // INTEGER r
    der_sig[idx++] = 0x02;  // INTEGER tag
    der_sig[idx++] = r_len;
    if (r_pad) der_sig[idx++] = 0x00;
    memcpy(der_sig + idx, r + r_start, 32 - r_start);
    idx += 32 - r_start;

    // INTEGER s
    der_sig[idx++] = 0x02;  // INTEGER tag
    der_sig[idx++] = s_len;
    if (s_pad) der_sig[idx++] = 0x00;
    memcpy(der_sig + idx, s + s_start, 32 - s_start);
    idx += 32 - s_start;

    return idx;
}

// ============================================================================
// BASE64 ENCODING
// ============================================================================

String base64Encode(const uint8_t* data, size_t length) {
    String encoded;
    int i = 0;
    int j = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];

    while (length--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i < 4; i++)
                encoded += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            encoded += base64_chars[char_array_4[j]];

        while(i++ < 3)
            encoded += '=';
    }

    return encoded;
}

// ============================================================================
// RANDOM NUMBER GENERATOR (Required by uECC)
// ============================================================================

static int RNG(uint8_t *dest, unsigned size) {
    // ESP8266 has hardware random number generator
    // This is cryptographically secure
    while (size) {
        uint32_t random_value = RANDOM_REG32;
        uint8_t bytes_to_copy = (size < 4) ? size : 4;
        
        memcpy(dest, &random_value, bytes_to_copy);
        dest += bytes_to_copy;
        size -= bytes_to_copy;
    }
    return 1;  // Success
}

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

bool initializeCrypto() {
    Serial.println("\n[CRYPTO] ═══════════════════════════════════");
    Serial.println("[CRYPTO] Initializing Cryptographic Module");
    Serial.println("[CRYPTO] ═══════════════════════════════════");
    
    // Set the curve to P-256 (secp256r1)
    curve = uECC_secp256r1();
    
    if (curve == NULL) {
        Serial.println("[CRYPTO] Failed to initialize curve!");
        cryptoReady = false;
        return false;
    }
    
    Serial.println("[CRYPTO] Curve: NIST P-256 (secp256r1)");
    
    // Set random number generator
    uECC_set_rng(&RNG);
    Serial.println("[CRYPTO] RNG initialized (ESP8266 hardware RNG)");
    
    // Verify private key length
    Serial.print("[CRYPTO] Private key size: ");
    Serial.print(sizeof(ECDSA_PRIVATE_KEY));
    Serial.println(" bytes");
    
    if (sizeof(ECDSA_PRIVATE_KEY) != 32) {
        Serial.println("[CRYPTO] Invalid private key size! Expected 32 bytes.");
        cryptoReady = false;
        return false;
    }
    
    Serial.println("[CRYPTO] Private key validated");
    Serial.println("[CRYPTO] Cryptographic module ready");
    Serial.println("[CRYPTO] ═══════════════════════════════════\n");
    
    cryptoReady = true;
    return true;
}

bool isCryptoReady() {
    return cryptoReady;
}

String signMessage(const String& message) {
    if (!cryptoReady) {
        Serial.println("[CRYPTO] Crypto not initialized!");
        return "";
    }
    
    Serial.println("\n[CRYPTO] ───────────────────────────────────");
    Serial.println("[CRYPTO] Signing Message");
    Serial.println("[CRYPTO] ───────────────────────────────────");
    
    // Step 1: Compute SHA-256 hash of the message
    Serial.println("[CRYPTO] Step 1: Computing SHA-256 hash...");
    
    uint8_t hash[32];  // SHA-256 produces 32-byte hash
    
    // Use ESP8266's built-in SHA256 from BearSSL
    br_sha256_context sha_ctx;
    br_sha256_init(&sha_ctx);
    br_sha256_update(&sha_ctx, message.c_str(), message.length());
    br_sha256_out(&sha_ctx, hash);
    
    Serial.print("[CRYPTO] Message length: ");
    Serial.print(message.length());
    Serial.println(" bytes");
    
    Serial.print("[CRYPTO] Hash (first 16 bytes): ");
    for (int i = 0; i < 16; i++) {
        if (hash[i] < 0x10) Serial.print("0");
        Serial.print(hash[i], HEX);
    }
    Serial.println("...");
    
    // Step 2: Sign the hash with ECDSA
    Serial.println("[CRYPTO] Step 2: Signing hash with ECDSA...");
    
    uint8_t signature[64];  // ECDSA P-256 signature is 64 bytes (r=32, s=32)
    
    int result = uECC_sign(ECDSA_PRIVATE_KEY, hash, sizeof(hash), signature, curve);
    
    if (result == 0) {
        Serial.println("[CRYPTO] Signing failed!");
        return "";
    }
    
    Serial.println("[CRYPTO] Raw signature created (64 bytes)");

    // Step 3: Convert raw signature to DER format (required by server)
    Serial.println("[CRYPTO] Step 3: Converting to DER format...");

    uint8_t der_signature[72];  // Max DER size for P-256: 2 + 2 + 33 + 2 + 33 = 72
    size_t der_len = encodeSignatureToDER(signature, der_signature);

    Serial.print("[CRYPTO] DER signature length: ");
    Serial.print(der_len);
    Serial.println(" bytes");

    Serial.print("[CRYPTO] DER signature (first 16 bytes): ");
    for (size_t i = 0; i < 16 && i < der_len; i++) {
        if (der_signature[i] < 0x10) Serial.print("0");
        Serial.print(der_signature[i], HEX);
    }
    Serial.println("...");

    // Step 4: Encode DER signature to Base64
    Serial.println("[CRYPTO] Step 4: Encoding to Base64...");

    String encodedSignature = base64Encode(der_signature, der_len);
    
    Serial.print("[CRYPTO] Base64 signature: ");
    Serial.println(encodedSignature);
    Serial.print("[CRYPTO] Base64 length: ");
    Serial.print(encodedSignature.length());
    Serial.println(" characters");
    
    Serial.println("[CRYPTO] Signing complete");
    Serial.println("[CRYPTO] ───────────────────────────────────\n");
    
    return encodedSignature;
}