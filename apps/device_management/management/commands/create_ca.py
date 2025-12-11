import os
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand
from django.conf import settings
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class Command(BaseCommand):
    help = 'Create a Certificate Authority (CA) for device management'

    def handle(self, *args, **options):
        # Check if CA already exists
        if os.path.exists(settings.CA_PRIVATE_KEY_PATH) and os.path.exists(settings.CA_CERTIFICATE_PATH):
            self.stdout.write(self.style.WARNING('CA already exists. Skipping creation.'))
            return
        
        # Create ca/ directory if it doesn't exist
        os.makedirs(settings.CA_DIR, exist_ok=True)
        
        self.stdout.write('Generating CA private key...')

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
        )
        
        self.stdout.write(self.style.SUCCESS('CA private key generated (4096-bit RSA)'))

        # Code below was coppied from https://cryptography.io/en/latest/x509/tutorial/#creating-a-certificate-signing-request-csr
        # with some small adjustments
        # START OF COPIED CODE
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"EU"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Europe"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"C3DS Prototype"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"C3DS Root CA"),
        ])
        
        ca_cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=5*365)  # 5 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0), # this is to be able to create other certs signed by this CA, but not further CAs
            critical=True,
        ).sign(private_key, hashes.SHA256())
        
        self.stdout.write(self.style.SUCCESS('CA certificate created (valid for 5 years)'))
        # END OF COPIED CODE

        # Save private key
        with open(settings.CA_PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        self.stdout.write(self.style.SUCCESS(f'CA private key saved to {settings.CA_PRIVATE_KEY_PATH}'))

        # Save certificate
        with open(settings.CA_CERTIFICATE_PATH, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

        self.stdout.write(self.style.SUCCESS(f'CA certificate saved to {settings.CA_CERTIFICATE_PATH}'))

        # restric the permissions of the private key file
        try:
            os.chmod(settings.CA_PRIVATE_KEY_PATH, 0o600)
            self.stdout.write(self.style.SUCCESS(f'Set permissions of CA private key to 600'))
        except Exception as e:
            self.stdout.write(self.style.WARNING(f'Could not set permissions of CA private key: {e}'))
        
        self.stdout.write(self.style.SUCCESS('CA creation process completed successfully.'))