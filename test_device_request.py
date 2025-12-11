import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

# Configuration
CERT_PATH = Path(r"C:\Users\pawel\Downloads\Sensor device 1_certificate_bundle")
DEVICE_CERT_FILE = CERT_PATH / "Sensor device 1_certificate.pem"
DEVICE_KEY_FILE = CERT_PATH / "Sensor device 1_private_key.pem"

# Sample message
message_data = {
    "message_type": "heartbeat",
    "timestamp": "2024-12-11T10:30:00Z",
    "data": {
        "status": "online",
        "battery": 85
    }
}

def main():
    # Read device certificate
    with open(DEVICE_CERT_FILE, 'rb') as f:
        device_cert_pem = f.read()
    
    # Read device private key
    with open(DEVICE_KEY_FILE, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    
    # Convert message to JSON bytes
    message_json = json.dumps(message_data)
    message_bytes = message_json.encode('utf-8')
    
    # Sign the message with private key
    signature = private_key.sign(
        message_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    # Encode for HTTP headers
    cert_base64 = base64.b64encode(device_cert_pem).decode('utf-8')
    signature_base64 = base64.b64encode(signature).decode('utf-8')
    
    # Print instructions for Postman
    print("=" * 80)
    print("POSTMAN CONFIGURATION")
    print("=" * 80)
    print("\nURL: http://localhost:8000/api/device/message/")
    print("Method: POST")
    print("\n--- HEADERS ---")
    print(f"\nX-Device-Certificate:")
    print(cert_base64)
    print(f"\nX-Device-Signature:")
    print(signature_base64)
    print(f"\nContent-Type:")
    print("application/json")
    print("\n--- BODY (raw JSON) ---")
    print(message_json)
    print("\n" + "=" * 80)

if __name__ == "__main__":
    main()