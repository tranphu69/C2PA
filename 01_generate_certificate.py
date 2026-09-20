import argparse
from cert_manager import create_root_ca, create_author_cert, ROOT_CERT_PATH

DEMO_IDENTITIES = [
    ("Trần Văn A", "VietNews Media"),
    ("Nguyễn Văn B", "VietNews Media"),
    ("Kẻ Giả Mạo", "Unknown Blog"),
]

def main():
    parser = argparse.ArgumentParser(description="Tạo Root CA và chứng chỉ tác giả cho demo C2PA")
    parser.add_argument("--author", help="Tên tác giả cần cấp chứng chỉ")
    parser.add_argument("--org", default="Independent", help="Tổ chức của tác giả")
    parser.add_argument("--force", action="store_true", help="Ghi đè khóa/chứng chỉ đã có")
    args = parser.parse_args()
    created = create_root_ca(force=args.force)
    print(f"✅ Đã tạo Root CA mới: {ROOT_CERT_PATH}" if created else f"ℹ️ Root CA đã có sẵn: {ROOT_CERT_PATH}")
    if created and args.force:
        print("⚠️ Root CA mới nên các chứng chỉ tác giả cũ (nếu có) không còn khớp. "
              "Hãy tạo lại chúng, và xóa c2pa_watermark_app/history.db nếu muốn Trust List sạch.")
    identities = [(args.author, args.org)] if args.author else DEMO_IDENTITIES
    for name, org in identities:
        try:
            info = create_author_cert(name, org, force=args.force)
            print(f"✅ {info['cn']} ({info['org']}) | serial={info['serial'][:16]}... | hết hạn {info['not_after']}")
        except FileExistsError as e:
            print(f"ℹ️ {e} (dùng --force để tạo lại)")
    print("\nXong. Bước tiếp theo: chạy app, vào tab 'Quản lý Trust List' để PHÊ DUYỆT tác giả tin cậy.")
    print("Các file es256_certs.pem / es256_private.key cũ không còn được dùng, có thể xóa.")

if __name__ == "__main__":
    main()