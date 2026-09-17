import os
import cv2
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from app import verify_image

RESULT_DIR = "robustness_results"
os.makedirs(RESULT_DIR, exist_ok=True)

def apply_jpeg_compress(img, quality):
    """Nén JPEG ở mức quality (%) — mô phỏng việc MXH nén ảnh khi upload."""
    path = os.path.join(RESULT_DIR, f"_tmp_jpeg_{quality}.jpg")
    cv2.imwrite(path, img, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
    return cv2.imread(path)

def apply_resize(img, scale):
    """Thu nhỏ ảnh theo tỷ lệ scale — mô phỏng MXH resize ảnh để tiết kiệm băng thông."""
    h, w = img.shape[:2]
    return cv2.resize(img, (max(1, int(w * scale)), max(1, int(h * scale))),
                       interpolation=cv2.INTER_AREA)

def apply_crop(img, crop_ratio):
    """Cắt bớt viền ảnh theo tỷ lệ crop_ratio (tổng 2 bên) — mô phỏng crop khi đăng bài."""
    h, w = img.shape[:2]
    dy, dx = int(h * crop_ratio / 2), int(w * crop_ratio / 2)
    return img[dy:h - dy, dx:w - dx]

def apply_gaussian_noise(img, sigma):
    """Thêm nhiễu Gauss — mô phỏng suy hao khi chụp lại màn hình / re-scan."""
    noise = np.random.normal(0, sigma, img.shape).astype(np.float32)
    noisy = img.astype(np.float32) + noise
    return np.clip(noisy, 0, 255).astype(np.uint8)

def apply_screenshot_simulation(img):
    """Mô phỏng việc người dùng CHỤP MÀN HÌNH ảnh thay vì tải file gốc:
    resize theo độ phân giải màn hình phổ biến + nhiễu nhẹ + nén JPEG 85%."""
    h, w = img.shape[:2]
    target_w = min(w, 1080)
    resized = cv2.resize(img, (target_w, int(h * target_w / w)))
    noisy = apply_gaussian_noise(resized, sigma=2)
    return apply_jpeg_compress(noisy, quality=85)

def run_transform_and_verify(img, transform_name, transform_fn, save_name):
    transformed = transform_fn(img)
    out_path = os.path.join(RESULT_DIR, save_name)
    cv2.imwrite(out_path, transformed)
    report, _ = verify_image(out_path)
    c2pa_ok = "LỚP 1 - C2PA MANIFEST]: THÀNH CÔNG" in report
    watermark_ok = "LỚP 2 - INVISIBLE WATERMARK]: THÀNH CÔNG" in report
    return {
        "transform": transform_name,
        "file": out_path,
        "c2pa_ok": c2pa_ok,
        "watermark_ok": watermark_ok,
        "report": report,
    }

def main(signed_image_path):
    img = cv2.imread(signed_image_path)
    if img is None:
        raise FileNotFoundError(f"Không đọc được ảnh: {signed_image_path}")
    transforms = []
    for q in [90, 70, 50, 30]:
        transforms.append((f"JPEG_Q{q}", lambda im, q=q: apply_jpeg_compress(im, q), f"jpeg_q{q}.jpg"))
    for s in [0.5, 0.25]:
        transforms.append((f"Resize_{int(s*100)}%", lambda im, s=s: apply_resize(im, s), f"resize_{int(s*100)}.png"))
    transforms.append(("Crop_5%", lambda im: apply_crop(im, 0.05), "crop_5.png"))
    transforms.append(("Crop_10%", lambda im: apply_crop(im, 0.10), "crop_10.png"))
    for sigma in [5, 10, 20]:
        transforms.append((f"Noise_sigma{sigma}", lambda im, sg=sigma: apply_gaussian_noise(im, sg), f"noise_{sigma}.png"))
    transforms.append(("Screenshot_sim", apply_screenshot_simulation, "screenshot_sim.jpg"))
    results = []
    print(f"Đang kiểm thử robustness trên: {signed_image_path}\n")
    for name, fn, fname in transforms:
        print(f"[*] {name} ...", end=" ")
        try:
            r = run_transform_and_verify(img, name, fn, fname)
        except Exception as e:
            r = {"transform": name, "file": fname, "c2pa_ok": False, "watermark_ok": False,
                 "report": f"LỖI KHI XỬ LÝ: {e}"}
        results.append(r)
        print(f"C2PA={'OK' if r['c2pa_ok'] else 'FAIL'} | Watermark(fallback)={'OK' if r['watermark_ok'] else 'FAIL'}")
    csv_path = os.path.join(RESULT_DIR, "robustness_results.csv")
    with open(csv_path, "w", encoding="utf-8") as f:
        f.write("transform,c2pa_ok,watermark_ok\n")
        for r in results:
            f.write(f"{r['transform']},{r['c2pa_ok']},{r['watermark_ok']}\n")
    print(f"\n[+] Đã lưu CSV: {csv_path}")
    detail_path = os.path.join(RESULT_DIR, "robustness_detail_reports.txt")
    with open(detail_path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(f"===== {r['transform']} =====\n{r['report']}\n\n")
    print(f"[+] Đã lưu chi tiết report: {detail_path}")
    names = [r["transform"] for r in results]
    wm_vals = [1 if r["watermark_ok"] else 0 for r in results]
    c2pa_vals = [1 if r["c2pa_ok"] else 0 for r in results]
    x = np.arange(len(names))
    width = 0.35
    fig, ax = plt.subplots(figsize=(13, 5))
    ax.bar(x - width / 2, c2pa_vals, width, label="C2PA còn nguyên")
    ax.bar(x + width / 2, wm_vals, width, label="Watermark giải mã được (fallback)")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=45, ha="right")
    ax.set_ylim(0, 1.2)
    ax.set_ylabel("Thành công (1) / Thất bại (0)")
    ax.set_title("Độ bền vững của C2PA và Watermark trước các phép biến đổi ảnh")
    ax.legend()
    plt.tight_layout()
    chart_path = os.path.join(RESULT_DIR, "robustness_chart.png")
    plt.savefig(chart_path, dpi=150)
    print(f"[+] Đã lưu biểu đồ: {chart_path}")
    total = len(results)
    c2pa_rate = sum(c2pa_vals) / total * 100
    wm_rate = sum(wm_vals) / total * 100
    print("\n================ TỔNG KẾT ================")
    print(f"Tỷ lệ C2PA còn nguyên sau biến đổi     : {c2pa_rate:.1f}% ({sum(c2pa_vals)}/{total})")
    print(f"Tỷ lệ Watermark giải mã được (fallback): {wm_rate:.1f}% ({sum(wm_vals)}/{total})")
    print("=" * 44)
    print("\nGợi ý cho báo cáo: nếu C2PA rate ~0%, nghĩa là bất kỳ phép biến đổi/")
    print("chuyển định dạng nào cũng phá vỡ Lớp 1 — đây là lý do vì sao cơ chế")
    print("fallback bằng watermark (Lớp 2) là thành phần BẮT BUỘC cho bài toán")
    print("chống tin giả trên mạng xã hội, chứ không thể chỉ dựa vào C2PA đơn thuần.")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True,
                         help="Đường dẫn ảnh đã ký C2PA + watermark (vd: processed/xxx_signed.png)")
    args = parser.parse_args()
    main(args.image)