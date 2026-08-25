# C3DS Device Integration Guide

**Version:** 1.0
**Endpoint:** `POST /api/device/message/`

This guide describes how to build a device that participates in the C3DS network. It covers the message format, authentication requirements, and the step-by-step process for sending a valid message to the server.

---

## Prerequisites

Before a device can send messages, it must be registered with a C3DS operator. The operator will provide you with:

- A **device certificate** (`.pem` file) — your device's identity, signed by the C3DS Certificate Authority
- A **private key** (`.key` file) — used to sign each message

Keep the private key secure. Do not transmit it or store it in plaintext if avoidable.

---

## Message Format

Messages are sent as JSON in the HTTP request body. The following fields are supported:

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `message_type` | string (max 50 chars) | Category of the message. See [Message Types](#message-types) below. |
| `timestamp` | string (ISO 8601) | The time the event was observed, in UTC. Example: `"2026-02-17T14:30:00Z"` |
| `data` | object | Arbitrary sensor payload. Structure is defined by the device builder. |

### Optional Fields in `data`

The `data` object is flexible — you can include any fields relevant to your sensor. However, the following fields are recognised by the dashboard and should be used where applicable:

| Field | Type | Description |
|-------|------|-------------|
| `confidence` | float (0.0–1.0) | How confident the device is in the detection. `1.0` = certain, `0.0` = no confidence. |

### Example Message Body

```json
{
    "message_type": "alert",
    "timestamp": "2026-02-17T14:30:00Z",
    "data": {
        "confidence": 0.87,
        "frequency_hz": 433920000,
        "signal_strength_dbm": -72,
        "duration_ms": 340
    }
}
```

```json
{
    "message_type": "heartbeat",
    "timestamp": "2026-02-17T14:00:00Z",
    "data": {
        "uptime_seconds": 86400,
        "battery_percent": 91
    }
}
```

---

## Message Types

The `message_type` field is a free-form string, but the following values are recommended for consistency:

| Value | When to use |
|-------|-------------|
| `alert` | A drone or suspicious signal has been detected |
| `heartbeat` | Periodic check-in to confirm the device is online |
| `status` | A change in device state (e.g. battery low, sensor fault) |
| `test` | During development and testing only |

---

## Authentication

C3DS uses **mutual certificate authentication** for device messages. Every request must include two custom HTTP headers.

### Required Headers

| Header | Value |
|--------|-------|
| `X-Device-Certificate` | Your device certificate (PEM format), encoded as Base64 |
| `X-Device-Signature` | A cryptographic signature of the raw request body, encoded as Base64 |

Both values must be Base64-encoded. Standard Base64 (not URL-safe) is expected.

---

## How to Send a Message: Step by Step

### Step 1 — Prepare the message body

Construct your JSON message as a UTF-8 encoded byte string. This exact byte string is what you will sign in the next step — do not modify it afterwards (e.g. do not re-serialise or pretty-print it).

```
body = utf8_encode({
    "message_type": "alert",
    "timestamp": "2026-02-17T14:30:00Z",
    "data": { "confidence": 0.87 }
})
```

### Step 2 — Sign the message body

Sign the raw message body bytes using your device's private key.

**If your device uses an RSA key:**
- Algorithm: RSA with PKCS#1 v1.5 padding
- Hash: SHA-256
- Input: the raw UTF-8 body bytes

**If your device uses an ECDSA key:**
- Algorithm: ECDSA
- Hash: SHA-256
- Input: the raw UTF-8 body bytes

The result is a binary signature. Base64-encode it for the header.

```
signature_bytes = sign(private_key, body)
signature_b64   = base64_encode(signature_bytes)
```

### Step 3 — Encode your certificate

Read your device certificate file (PEM format). Base64-encode the entire PEM content, including the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` lines.

```
cert_pem_bytes = read_file("device.pem")
cert_b64       = base64_encode(cert_pem_bytes)
```

### Step 4 — Send the HTTP request

Send an HTTPS POST request to the endpoint:

```
POST /api/device/message/
Content-Type: application/json
X-Device-Certificate: <cert_b64>
X-Device-Signature: <signature_b64>

<body>
```

> **Important:** Use HTTPS in production. HTTP requests will not be accepted by a correctly configured server.

---

## Server Validation Steps

When the server receives your request, it performs the following checks in order. A failure at any step returns an error and the message is rejected.

1. **Headers present** — Both `X-Device-Certificate` and `X-Device-Signature` must be included.
2. **Certificate format** — The certificate must be a valid X.509 PEM certificate.
3. **CA signature** — The certificate must have been signed by the C3DS Certificate Authority.
4. **Certificate validity period** — The current time must fall within the certificate's `notBefore` and `notAfter` dates.
5. **Device lookup** — The device UUID (from the certificate's Common Name) must exist in the database.
6. **Device not revoked** — Devices with a `REVOKED` status are rejected.
7. **Message signature** — The signature in `X-Device-Signature` must match the request body, verified using the public key in the certificate.
8. **Valid JSON** — The request body must parse as valid JSON.

If all checks pass, the message is stored and the device status is automatically set to `ACTIVE`.

---

## Response Format

### Success

```json
{
    "status": "success",
    "saved": true,
    "device_id": "e3bf7037-ca57-4928-9476-0e40e8b5d30d",
    "timestamp": "2026-02-17T14:30:05.123456Z",
    "message": "Message stored successfully."
}
```

HTTP status: `200 OK`

### Error Responses

| HTTP Status | Meaning |
|-------------|---------|
| `400 Bad Request` | Malformed certificate, signature, or JSON body |
| `401 Unauthorized` | Missing headers, invalid certificate, or signature mismatch |
| `403 Forbidden` | Device has been revoked |
| `404 Not Found` | Device UUID not found in the database |
| `500 Internal Server Error` | Server configuration error (contact operator) |

Error responses include a JSON body:

```json
{
    "error": "Description of what went wrong."
}
```

---

## Timestamp Handling

- Always use **ISO 8601 format** with UTC timezone: `"2026-02-17T14:30:00Z"`
- The `timestamp` field should reflect when the **event occurred**, not when the message was sent
- If no `timestamp` is provided, the server will use the time it received the message

---

## Security Notes

- **Never share your private key.** It is the sole proof of your device's identity.
- **Do not reuse signatures.** Always sign the current message body fresh — replaying a previous signature will fail because the body will differ.
- **Certificate expiry.** Certificates have a fixed validity period. Contact your operator before your certificate expires to arrange renewal. An expired certificate will be rejected.
- **Revocation.** If your device is lost, stolen, or compromised, contact your operator immediately to have the certificate revoked.

---

## Frequently Asked Questions

**Can I send any data in the `data` field?**
Yes. The `data` field accepts any valid JSON object. Structure it however makes sense for your sensor. Fields not recognised by the dashboard are stored but not displayed.

**What if my clock is wrong?**
The server does not validate that your `timestamp` matches the server's clock. However, an accurate timestamp is important for the dashboard to display events in the correct order. Use NTP to keep your device clock synchronised.

**What happens if the server fails to store my message?**
The response will include `"saved": false` but will still return HTTP `200`. This indicates a server-side storage failure. Your device does not need to retry unless you consider the data critical.

**Does the order of JSON keys matter?**
No, but the **exact bytes** of the body you sign must be the same bytes you send. Do not re-serialise, reformat, or compress the body between signing and sending.