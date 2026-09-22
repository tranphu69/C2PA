import os
import time
import c2pa
from cert_manager import load_signing_material, get_cert_info
from app import sign_es256, verify_image, utc_now_iso, APP_AGENT, DIGITAL_SOURCE_TYPE

KB4_DIR = "kb4_name_mismatch"
os.makedirs(KB4_DIR, exist_ok=True)

def make_signer_for(author_name):
    chain_pem, key_pem = load_signing_material(author_name)
    signer = c2pa.create_signer(
        lambda data: sign_es256(data, key_pem),
        c2pa.SigningAlg.ES256,
        chain_pem,
        None,
    )
    return signer, get_cert_info(chain_pem)

def sign_with_fake_claimed_name(image_path, real_identity, fake_claimed_name):
    signer, cert_info = make_signer_for(real_identity)
    manifest = {
        "claim_generator": APP_AGENT,
        "assertions": [
            {
                "label": "stds.schema-org.CreativeWork",
                "data": {
                    "@context": "https://schema.org",
                    "@type": "CreativeWork",
                    "author": [{"@type": "Person", "name": fake_claimed_name}],
                },
            },
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [{
                        "action": "c2pa.created",
                        "when": utc_now_iso(),
                        "softwareAgent": APP_AGENT,
                        "digitalSourceType": DIGITAL_SOURCE_TYPE,
                    }]
                },
            },
        ],
    }
    base_name = os.path.splitext(os.path.basename(image_path))[0]
    ext = os.path.splitext(image_path)[1] or ".png"
    out_path = os.path.join(KB4_DIR, f"{base_name}_KB4_{int(time.time() * 1000)}{ext}")
    builder = c2pa.Builder(manifest)
    builder.sign_file(signer, image_path, out_path)
    print(f"[KB4] Ký bằng chứng chỉ THẬT của '{real_identity}' "
          f"(CN='{cert_info['cn']}', serial={cert_info['serial'][:12]}...)")
    print(f"[KB4] Nhưng manifest khai tên tác giả là: '{fake_claimed_name}'")
    print(f"[KB4] File đầu ra: {out_path}")
    return out_path

def main(image_path, real_identity="Trần Văn A", fake_claimed_name="Nguyễn Văn B"):
    out_path = sign_with_fake_claimed_name(image_path, real_identity, fake_claimed_name)
    report, _ = verify_image(out_path)
    result_path = os.path.join(KB4_DIR, "kb4_verify_report.txt")
    with open(result_path, "w", encoding="utf-8") as f:
        f.write(report)
    print("\n===== KẾT QUẢ XÁC MINH (verify_image) =====")
    print(report)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Chuẩn bị kịch bản KB4 - khai gian tên tác giả")
    parser.add_argument("--image", required=True, help="Ảnh gốc dùng để ký thử")
    parser.add_argument("--real-identity", default="Trần Văn A",
                         help="Danh tính có chứng chỉ THẬT, đã được phê duyệt trong Trust List")
    parser.add_argument("--fake-name", default="Nguyễn Văn B",
                         help="Tên tự khai trong manifest, khác CN của --real-identity")
    args = parser.parse_args()
    main(args.image, args.real_identity, args.fake_name)