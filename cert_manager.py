import os
import re
import hashlib
import datetime
import unicodedata
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

CERTS_DIR = "certs"
ROOT_CERT_PATH = os.path.join(CERTS_DIR, "root_ca.pem")
ROOT_KEY_PATH = os.path.join(CERTS_DIR, "root_ca.key")
AUTHORS_DIR = os.path.join(CERTS_DIR, "authors")
CHAIN_FILENAME = "cert_chain.pem"
KEY_FILENAME = "private.key"
ROOT_ORG = "C2PA Demo Trust Root"
ROOT_CN = "C2PA Demo Root CA"

def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc)

def _cert_time(cert, attr):
    value = getattr(cert, attr + "_utc", None)
    if value is None:
        value = getattr(cert, attr).replace(tzinfo=datetime.timezone.utc)
    return value

def slugify(name: str) -> str:
    name = name.replace("đ", "d").replace("Đ", "D")
    name = unicodedata.normalize("NFKD", name)
    name = "".join(c for c in name if not unicodedata.combining(c))
    name = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").lower()
    return name or "author"

def _write_private_key(path, key):
    with open(path, "wb") as f:
        f.write(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

def _load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

def load_cert_file(path):
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def create_root_ca(force=False) -> bool:
    os.makedirs(CERTS_DIR, exist_ok=True)
    if os.path.exists(ROOT_CERT_PATH) and os.path.exists(ROOT_KEY_PATH) and not force:
        return False
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ROOT_ORG),
            x509.NameAttribute(NameOID.COMMON_NAME, ROOT_CN),
        ]
    )
    now = _utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    _write_private_key(ROOT_KEY_PATH, key)
    with open(ROOT_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return True

def author_paths(author_name: str) -> dict:
    folder = os.path.join(AUTHORS_DIR, slugify(author_name))
    return {
        "dir": folder,
        "chain": os.path.join(folder, CHAIN_FILENAME),
        "key": os.path.join(folder, KEY_FILENAME),
    }

def create_author_cert(author_name, organization="Independent", force=False, days=365):
    author_name = author_name.strip()
    if not author_name:
        raise ValueError("Tên tác giả không được để trống")
    if len(author_name) > 64:
        raise ValueError("Tên tác giả tối đa 64 ký tự (giới hạn của trường CN)")
    if not (os.path.exists(ROOT_CERT_PATH) and os.path.exists(ROOT_KEY_PATH)):
        raise FileNotFoundError("Chưa có Root CA. Hãy chạy create_root_ca() trước.")
    paths = author_paths(author_name)
    if os.path.exists(paths["chain"]) and not force:
        raise FileExistsError(f"Đã có chứng chỉ cho '{author_name}' ({paths['dir']})")
    root_cert = load_cert_file(ROOT_CERT_PATH)
    root_key = _load_private_key(ROOT_KEY_PATH)
    key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization or "Independent"),
            x509.NameAttribute(NameOID.COMMON_NAME, author_name),
        ]
    )
    now = _utcnow()
    leaf = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
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
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256(), default_backend())
    )
    os.makedirs(paths["dir"], exist_ok=True)
    _write_private_key(paths["key"], key)
    with open(paths["chain"], "wb") as f:
        f.write(leaf.public_bytes(serialization.Encoding.PEM))
        f.write(root_cert.public_bytes(serialization.Encoding.PEM))
    with open(paths["chain"], "rb") as f:
        return get_cert_info(f.read())

def load_signing_material(author_name: str):
    p = author_paths(author_name)
    if not (os.path.exists(p["chain"]) and os.path.exists(p["key"])):
        raise FileNotFoundError(
            f"Chưa có chứng chỉ cho '{author_name}'.\n"
            f'Chạy: python 01_generate_certificate.py --author "{author_name}"'
        )
    with open(p["chain"], "rb") as f:
        chain = f.read()
    with open(p["key"], "rb") as f:
        key = f.read()
    return chain, key

def get_cert_info(pem_bytes: bytes) -> dict:
    cert = x509.load_pem_x509_certificate(pem_bytes, default_backend())
    def attr(oid):
        vals = cert.subject.get_attributes_for_oid(oid)
        return vals[0].value if vals else ""
    issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    der = cert.public_bytes(serialization.Encoding.DER)
    return {
        "cn": attr(NameOID.COMMON_NAME),
        "org": attr(NameOID.ORGANIZATION_NAME),
        "serial": str(cert.serial_number),
        "sha256": hashlib.sha256(der).hexdigest(),
        "not_after": _cert_time(cert, "not_valid_after").strftime("%Y-%m-%d"),
        "subject": cert.subject.rfc4514_string(),
        "issuer_cn": issuer_cn[0].value if issuer_cn else "",
    }

def list_authors() -> list:
    out = []
    if not os.path.isdir(AUTHORS_DIR):
        return out
    for slug in sorted(os.listdir(AUTHORS_DIR)):
        chain = os.path.join(AUTHORS_DIR, slug, CHAIN_FILENAME)
        if not os.path.exists(chain):
            continue
        try:
            with open(chain, "rb") as f:
                info = get_cert_info(f.read())
            info["slug"] = slug
            info["name"] = info["cn"]
            out.append(info)
        except Exception:
            continue
    return sorted(out, key=lambda a: a["name"])

def verify_issued_by_root(pem_bytes: bytes):
    if not os.path.exists(ROOT_CERT_PATH):
        return False, "Chưa có Root CA"
    root = load_cert_file(ROOT_CERT_PATH)
    leaf = x509.load_pem_x509_certificate(pem_bytes, default_backend())
    if leaf.issuer != root.subject:
        return False, "Issuer của chứng chỉ không phải Root CA của hệ thống"
    try:
        root.public_key().verify(
            leaf.signature,
            leaf.tbs_certificate_bytes,
            ec.ECDSA(leaf.signature_hash_algorithm),
        )
    except InvalidSignature:
        return False, "Chữ ký của Root CA trên chứng chỉ không hợp lệ"
    now = _utcnow()
    if not (_cert_time(leaf, "not_valid_before") <= now <= _cert_time(leaf, "not_valid_after")):
        return False, "Chứng chỉ đã hết hạn hoặc chưa có hiệu lực"
    return True, "OK"