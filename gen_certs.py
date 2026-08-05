import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
subject = issuer = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "C2PA Test Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "C2PA ES256 Demo Cert"),
    ]
)
builder = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(
        datetime.datetime.now(datetime.timezone.utc)
        + datetime.timedelta(days=365)
    )
    .add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    )
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
        critical=False,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
        critical=False,
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False,
    )
)
cert = builder.sign(private_key, hashes.SHA256(), default_backend())
with open("es256_private.key", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
with open("es256_certs.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
print("✅ Đã tạo lại cặp file es256_certs.pem và es256_private.key thành công!")