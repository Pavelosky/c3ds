from datetime import datetime, timedelta
from django.conf import settings
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
import pytz
from apps.device_management.models import CertificateAlgorithm

def generate_device_certificate(device):
    """
    Generate an X.509 certificate for a device signed by the CA.
    Supporting RSA and ECDSA based on settings.
    
    Args:
        device: Device model instance with certificate_algorithm attribute.
        
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

    # Generate device private key based on the selected algorithm
    algorithm = device.certificate_algorithm

    if algorithm == CertificateAlgorithm.RSA_2048:
        device_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # Smaller than CA (4096) but still secure
    )
        hash_algorithm = hashes.SHA256()

    elif algorithm == CertificateAlgorithm.RSA_4096:
        device_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,  # Same as CA
    )
        hash_algorithm = hashes.SHA256()

    # Equivalent to RSA 2048 in security level
    elif algorithm == CertificateAlgorithm.ECDSA_P256:
        device_private_key = ec.generate_private_key(
            ec.SECP256R1()  # P-256 curve
    )
        hash_algorithm = hashes.SHA256()

    # Equivalent to RSA 3072 in security level
    elif algorithm == CertificateAlgorithm.ECDSA_P384:
        device_private_key = ec.generate_private_key(
            ec.SECP384R1()  # P-384 curve
    )
        hash_algorithm = hashes.SHA384()

    else:
        raise ValueError("Unsupported certificate algorithm")



    # Code below was coppied from https://cryptography.io/en/latest/x509/tutorial/#creating-a-certificate-signing-request-csr
    # with some small adjustments
    # START OF COPIED CODE
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
    ).sign(ca_private_key, hash_algorithm)  # Signed with hash algorithm based on key type

    # Convert to PEM format for storage/transmission
    cert_pem = device_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    
    private_key_pem = device_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    # END OF COPIED CODE

    # Get expiry date from certificate and make it timezone-aware
    expiry_date = device_cert.not_valid_after.replace(tzinfo=pytz.UTC)
    

    # This is replaced with two lines below because the change in models.py caused by SQLite limitations
    # Needs to be reverted when PostgreSQL is used.
    
    ### START OF SQLITE WORKAROUND ###
    # return cert_pem, private_key_pem, serial_number, expiry_date

    # Convert serial number to hex string for storage
    # TODO: Revert to integer when migrating to PostgreSQL (code above)
    serial_hex = format(serial_number, 'x')
    
    return cert_pem, private_key_pem, serial_hex, expiry_date
    ### END OF SQLITE WORKAROUND ###