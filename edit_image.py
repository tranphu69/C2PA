import argparse
import sys
import cv2

def main():
    p = argparse.ArgumentParser(description="Cắt ảnh đơn giản")
    p.add_argument("input", help="Ảnh đầu vào")
    p.add_argument("output", help="Ảnh đầu ra (nên dùng .png)")
    p.add_argument("--percent", type=float, default=15, help="Phần trăm cắt bỏ mỗi cạnh (mặc định 15)")
    p.add_argument("--box", type=int, nargs=4, metavar=("X1", "Y1", "X2", "Y2"),
                   help="Cắt theo tọa độ pixel thay cho --percent")
    args = p.parse_args()
    img = cv2.imread(args.input)
    if img is None:
        sys.exit(f"Không đọc được ảnh: {args.input}")
    h, w = img.shape[:2]
    if args.box:
        x1, y1, x2, y2 = args.box
    else:
        dx, dy = int(w * args.percent / 100), int(h * args.percent / 100)
        x1, y1, x2, y2 = dx, dy, w - dx, h - dy
    if not (0 <= x1 < x2 <= w and 0 <= y1 < y2 <= h):
        sys.exit(f"Vùng cắt không hợp lệ. Ảnh gốc rộng {w}px, cao {h}px.")
    cv2.imwrite(args.output, img[y1:y2, x1:x2])
    print(f"Đã cắt {w}x{h} -> {x2 - x1}x{y2 - y1}, lưu tại {args.output}")


if __name__ == "__main__":
    main()