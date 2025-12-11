from datetime import datetime, timedelta
from django.conf import settings
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

def generate_device_certificate(device):
    """
    Generate an X.509 certificate for a device signed by the CA.
    
    Args:
        device: Device model instance
        
    Returns:
        tuple: (certificate_pem, private_key_pem, serial_number)
    """
    # Load CA private key
    with open(settings.CA_PRIVATE_KEY_PATH, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    
    # Load CA certificate
    with open(settings.CA_CERTIFICATE_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Generate device private key
    device_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,  # Smaller than CA (4096) but still secure
    )

    # Create device certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"EU"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"C3DS Network"),
        x509.NameAttribute(NameOID.COMMON_NAME, str(device.id)),  # Use device UUID
    ])

      # Generate serial number
    serial_number = x509.random_serial_number()

     # Build certificate
    device_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject  # Issued by systems CA
    ).public_key(
        device_private_key.public_key()
    ).serial_number(
        serial_number
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)  # Valid for 1 year for rotation purposes
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256())  # Signed by CA

    # Convert to PEM format for storage/transmission
    cert_pem = device_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    private_key_pem = device_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    # Get expiry date from certificate
    expiry_date = device_cert.not_valid_after
    
    """
    This is replaced due to the change in models.py caused by SQLite limitations
    Needs to be reverted when PostgreSQL is used.
    """
    # return cert_pem, private_key_pem, serial_number, expiry_date

    # Convert serial number to hex string for storage
    serial_hex = format(serial_number, 'x')
    
    return cert_pem, private_key_pem, serial_hex, expiry_date