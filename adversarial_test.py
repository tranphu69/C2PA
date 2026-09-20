import os
import time
import datetime
import c2pa
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from app import sign_es256, verify_image

ATTACKER_DIR = "adversarial_results"
os.makedirs(ATTACKER_DIR, exist_ok=True)
ATTACKER_KEY_PATH = os.path.join(ATTACKER_DIR, "attacker_private.key")
ATTACKER_CERT_PATH = os.path.join(ATTACKER_DIR, "attacker_certs.pem")

def generate_attacker_keypair_and_cert():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "XX"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Unverified Self-Signed Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Attacker Fake Cert (Not a Trusted CA)"),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
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
    with open(ATTACKER_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(ATTACKER_CERT_PATH, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Đã tạo cặp khóa 'kẻ tấn công' (self-signed, không thuộc CA nào):")
    print(f"    - {ATTACKER_KEY_PATH}")
    print(f"    - {ATTACKER_CERT_PATH}")

def attacker_sign_fake_manifest(target_image_path, fake_author_name="Reuters Official"):
    fake_manifest = {
        "claim_generator": "C2PA_Watermark_App/1.0",
        "assertions": [
            {
                "label": "stds.schema-org.CreativeWork",
                "data": {
                    "@context": "https://schema.org",
                    "@type": "CreativeWork",
                    "author": [{"@type": "Person", "name": fake_author_name}],
                },
            },
            {
                "label": "c2pa.actions",
                "data": {"actions": [{
                    "action": "c2pa.created",
                    "when": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                }]},
            },
        ],
    }
    base_name, ext = os.path.splitext(os.path.basename(target_image_path))
    if not ext:
        ext = ".png"
    ts = int(time.time() * 1000)
    out_path = os.path.join(ATTACKER_DIR, f"{base_name}_FAKE_signed_{ts}{ext}")
    builder = c2pa.Builder(fake_manifest)
    with open(ATTACKER_CERT_PATH, "rb") as f:
        certs = f.read()
    with open(ATTACKER_KEY_PATH, "rb") as f:
        private_key_bytes = f.read()
    signer = c2pa.create_signer(
        lambda data: sign_es256(data, private_key_bytes),
        c2pa.SigningAlg.ES256,
        certs,
        None,
    )
    builder.sign_file(signer, target_image_path, out_path)
    print(f"[+] Đã tạo ảnh GIẢ MẠO đã ký: {out_path}")
    return out_path

def main(target_image_path, fake_author_name="Reuters Official"):
    print("BƯỚC 1: Tạo danh tính 'kẻ tấn công' (self-signed, ngoài trust-list)\n")
    generate_attacker_keypair_and_cert()
    print(f"\nBƯỚC 2: Ký Manifest C2PA giả, tự xưng tác giả là '{fake_author_name}'\n")
    fake_signed_path = attacker_sign_fake_manifest(target_image_path, fake_author_name)
    print("\nBƯỚC 3: Đưa ảnh giả mạo qua ĐÚNG cơ chế xác minh của hệ thống (verify_image)\n")
    report, _ = verify_image(fake_signed_path)
    result_path = os.path.join(ATTACKER_DIR, "adversarial_verify_report.txt")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(report)
    print("===== KẾT QUẢ XÁC MINH TỪ HỆ THỐNG =====")
    print(report)
    print("=" * 42)
    print(f"\n[+] Đã lưu report: {result_path}")
    c2pa_reported_valid = "LỚP 1 - C2PA MANIFEST]: THÀNH CÔNG" in report
    fake_author_shown = fake_author_name in report
    print("\n================ KẾT LUẬN ================")
    if c2pa_reported_valid and fake_author_shown:
        print("[!] PHÁT HIỆN LỖ HỔNG:")
        print(f"    Hệ thống báo C2PA 'THÀNH CÔNG' và hiển thị tác giả '{fake_author_name}'")
        print("    — dù chứng thư ký hoàn toàn tự tạo, KHÔNG thuộc bất kỳ CA/trust-list nào.")
        print("    => C2PA (trong cách triển khai hiện tại của ứng dụng) chỉ xác minh")
        print("       được TÍNH TOÀN VẸN của chữ ký (ảnh + manifest chưa bị sửa sau khi ký),")
        print("       KHÔNG xác minh được DANH TÍNH người ký có đáng tin hay không.")
        print("    => Để dùng cho bài toán chống tin giả, cần bổ sung bước kiểm tra")
        print("       certificate chain / trust-list (ví dụ theo C2PA Trust List chính thức,")
        print("       hoặc danh sách CA được tổ chức/tòa soạn công nhận) khi verify.")
    else:
        print("[i] Hệ thống KHÔNG báo 'THÀNH CÔNG' với chứng thư lạ — kiểm tra lại")
        print("    report chi tiết ở trên / file report để xác nhận nguyên nhân.")
    print("=" * 44)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True,
                         help="Ảnh bất kỳ (vd: ảnh AI-generated) để mô phỏng kẻ tấn công gắn manifest giả")
    parser.add_argument("--fake-author", default="Reuters Official",
                         help="Tên tác giả giả mạo muốn tự xưng (mặc định: 'Reuters Official')")
    args = parser.parse_args()
    main(args.image, args.fake_author)