import os
import json
import time
import sqlite3
import cv2
import numpy as np
from PIL import Image
from imwatermark import WatermarkEncoder, WatermarkDecoder
import c2pa
import gradio as gr
import difflib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

BASE_DIR = "c2pa_watermark_app"
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed")
DB_PATH = os.path.join(BASE_DIR, "history.db")
MIN_WM_SIZE = 256
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)
WATERMARK_TEXT = "ORIGIN_SECURE_ID"
WATERMARK_BITS_LEN = len(WATERMARK_TEXT) * 8

def sign_es256(data: bytes, private_key_pem: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Private key không phải là EC (Elliptic Curve) key hợp lệ cho ES256!")
    signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return signature

def check_certificate_files():
    print("🔍 KIỂM TRA CERTIFICATE FILES")
    cert_file = "es256_certs.pem"
    key_file = "es256_private.key"
    cert_exists = os.path.exists(cert_file)
    key_exists = os.path.exists(key_file)
    print(f"\n✓ {cert_file}: {'✅ TỒN TẠI' if cert_exists else '❌ KHÔNG TỒN TẠI'}")
    print(f"✓ {key_file}: {'✅ TỒN TẠI' if key_exists else '❌ KHÔNG TỒN TẠI'}")
    if not cert_exists or not key_exists:
        print("❌ LỖI: THIẾU CERTIFICATE FILES")
        raise FileNotFoundError(
            f"Thiếu certificate files!\n"
            f"Chạy: python 01_generate_certificate.py"
        )
    try:
        with open(cert_file, "rb") as f:
            cert_content = f.read()
            if b"-----BEGIN CERTIFICATE-----" not in cert_content:
                raise ValueError("Certificate format sai!")
            print(f"  Size: {len(cert_content)} bytes")
        with open(key_file, "rb") as f:
            key_content = f.read()
            if b"-----BEGIN PRIVATE KEY-----" not in key_content:
                raise ValueError("Private Key format sai!")
            print(f"  Size: {len(key_content)} bytes")
        print("\n✅ Certificate files hợp lệ!")
    except Exception as e:
        print(f"\n❌ Lỗi: {e}")
        raise
check_certificate_files()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            filename TEXT,
            original_file TEXT,
            action TEXT,
            c2pa_status TEXT,
            watermark_status TEXT,
            author TEXT,
            details TEXT,
            edit_type TEXT,
            edit_details TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS manifest_chain (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            image_filename TEXT,
            manifest_id TEXT,
            creator_author TEXT,
            created_timestamp TEXT,
            modifications TEXT,
            watermark_embedded TEXT,
            final_verification_status TEXT
        )
    """)
    conn.commit()
    conn.close()

def log_history(filename, action, c2pa_status, watermark_status, author, details, original_file=None, edit_type=None, edit_details=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO history 
        (timestamp, filename, original_file, action, c2pa_status, watermark_status, author, details, edit_type, edit_details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, filename, original_file, action, c2pa_status, watermark_status, author, details, edit_type, edit_details))
    conn.commit()
    conn.close()

def get_history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, timestamp, filename, original_file, action, c2pa_status, watermark_status, author, edit_type, details 
        FROM history ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    if not rows:
        return "<p style='color: #888;'>Chưa có dữ liệu lịch sử.</p>"
    html = """
    <table style="width:100%; border-collapse: collapse; text-align: left; font-size: 13px;">
    <tr style="background-color: #f2f2f2; border-bottom: 2px solid #ddd;">
        <th style="padding: 8px;">ID</th>
        <th style="padding: 8px;">Thời gian</th>
        <th style="padding: 8px;">File</th>
        <th style="padding: 8px;">File gốc</th>
        <th style="padding: 8px;">Hành động</th>
        <th style="padding: 8px;">C2PA Status</th>
        <th style="padding: 8px;">Watermark</th>
        <th style="padding: 8px;">Tác giả/Người sửa</th>
        <th style="padding: 8px;">Loại sửa</th>
        <th style="padding: 8px;">Chi tiết</th>
    </tr>
    """
    for r in rows:
        c2pa_col = r[5] or ""
        wm_col = r[6] or ""
        c2pa_color = "#28a745" if "Success" in c2pa_col or "Thành công" in c2pa_col or "Hợp lệ" in c2pa_col else ("#dc3545" if "Lỗi" in c2pa_col or "Không" in c2pa_col else "#6c757d")
        wm_color = "#28a745" if "Hợp lệ" in wm_col or "Thành công" in wm_col or "Đã nhúng" in wm_col else ("#dc3545" if "Không khớp" in wm_col or "Thất bại" in wm_col else "#6c757d")
        html += f"""
        <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 8px;">{r[0]}</td>
            <td style="padding: 8px;">{r[1]}</td>
            <td style="padding: 8px;"><b>{r[2]}</b></td>
            <td style="padding: 8px;">{r[3] if r[3] else '-'}</td>
            <td style="padding: 8px;">{r[4]}</td>
            <td style="padding: 8px; color: {c2pa_color}; font-weight: bold;">{r[5]}</td>
            <td style="padding: 8px; color: {wm_color}; font-weight: bold;">{r[6]}</td>
            <td style="padding: 8px;">{r[7] if r[7] else '-'}</td>
            <td style="padding: 8px;">{r[8] if r[8] else '-'}</td>
            <td style="padding: 8px;">{r[9]}</td>
        </tr>
        """
    html += "</table>"
    return html
init_db()

def add_edit_assertion(manifest_json, editor_name, edit_type, edit_description):
    if "assertions" not in manifest_json:
        manifest_json["assertions"] = []
    edit_assertion = {
        "label": "c2pa.actions",
        "data": {
            "actions": [
                {
                    "action": "c2pa.edited",
                    "editor": editor_name,
                    "when": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "edit_type": edit_type,
                    "description": edit_description
                }
            ]
        }
    }
    manifest_json["assertions"].append(edit_assertion)
    return manifest_json

def process_edited_image_with_c2pa(original_image_path, edited_image_path, editor_name, edit_type, edit_description):
    if original_image_path is None or edited_image_path is None:
        return None, "⚠️ Vui lòng cung cấp đầy đủ đường dẫn ảnh!", get_history()
    if not editor_name.strip():
        editor_name = "Anonymous Editor"
    try:
        original_manifest = {}
        try:
            reader = c2pa.Reader.from_file(original_image_path)
            manifest_store = json.loads(reader.json())
            active_key = manifest_store.get("active_manifest")
            if active_key:
                original_manifest = manifest_store["manifests"][active_key]
        except Exception:
            original_manifest = {"claim_generator": "C2PA_App/1.0", "assertions": []}
        new_manifest = {
            "claim_generator": "C2PA_Watermark_App/1.0",
            "assertions": [],
        }
        if "assertions" in original_manifest:
            for assertion in original_manifest["assertions"]:
                if "stds.schema-org.CreativeWork" in assertion.get("label", ""):
                    new_manifest["assertions"].append(assertion)
                    break
        new_manifest = add_edit_assertion(new_manifest, editor_name, edit_type, edit_description)
        base_name = os.path.splitext(os.path.basename(edited_image_path))[0]
        timestamp = int(time.time() * 1000)
        c2pa_edited_path = os.path.join(PROCESSED_DIR, f"{base_name}_{timestamp}_edited_signed.png")
        builder = c2pa.Builder(new_manifest)
        for assertion in new_manifest.get("assertions", []):
            print(f"  📝 Assertion: {assertion.get('label')}")
        with open("es256_certs.pem", "rb") as f:
            certs = f.read()
        with open("es256_private.key", "rb") as f:
            private_key = f.read()
        signer = c2pa.create_signer(
            lambda data: sign_es256(data, private_key),
            c2pa.SigningAlg.ES256,
            certs,
            None
        )
        builder.sign_file(signer, edited_image_path, c2pa_edited_path)
        log_history(
            filename=os.path.basename(c2pa_edited_path),
            original_file=os.path.basename(original_image_path),
            action="Chỉnh sửa ảnh",
            c2pa_status="Manifest cập nhật",
            watermark_status="Watermark giữ nguyên",
            author=editor_name,
            details=f"Mô tả: {edit_description}",
            edit_type=edit_type,
            edit_details=edit_description
        )
        msg = f"✅ Ảnh chỉnh sửa đã được ký C2PA thành công!\nFile mới: {c2pa_edited_path}"
        return c2pa_edited_path, msg, get_history()
    except Exception as e:
        error_msg = f"❌ Lỗi khi ký C2PA: {str(e)}"
        return None, error_msg, get_history()


def trace_edit_chain(image_path):
    if image_path is None:
        return "<p style='color: orange;'>⚠️ Vui lòng tải ảnh lên để kiểm tra chuỗi chỉnh sửa.</p>"
    try:
        reader = c2pa.Reader.from_file(image_path)
        manifest_store = json.loads(reader.json())
        trace_html = "<h3>📝 Chuỗi Chỉnh Sửa (Edit Chain)</h3>"
        for manifest_key, manifest_data in manifest_store.get("manifests", {}).items():
            trace_html += f"<p><b>Manifest ID:</b> {manifest_key}</p>"
            for assertion in manifest_data.get("assertions", []):
                if assertion.get("label") == "c2pa.actions":
                    actions = assertion.get("data", {}).get("actions", [])
                    for i, action in enumerate(actions, 1):
                        trace_html += "<div style='border-left: 3px solid #007bff; padding: 10px; margin: 5px 0; background-color: #f8f9fa;'>"
                        trace_html += f"<b>Lần {i}:</b> {action.get('action', 'N/A')}<br>"
                        if action.get('action') == 'c2pa.created':
                            trace_html += "<i>Ảnh gốc được tạo</i><br>"
                        elif action.get('action') == 'c2pa.edited':
                            trace_html += f"<b>Người chỉnh sửa:</b> {action.get('editor', 'Unknown')}<br>"
                            trace_html += f"<b>Thời gian:</b> {action.get('when', 'N/A')}<br>"
                            trace_html += f"<b>Loại:</b> {action.get('edit_type', 'N/A')}<br>"
                            trace_html += f"<b>Mô tả:</b> {action.get('description', 'N/A')}<br>"
                        trace_html += "</div>"
        return trace_html
    except Exception as e:
        return f"<p style='color: red;'>❌ Không thể đọc chuỗi chỉnh sửa C2PA: {str(e)}</p>"

def process_and_sign(image_path, author_name):
    if image_path is None:
        return None, "⚠️ Vui lòng tải ảnh lên trước!", get_history()
    if not author_name.strip():
        author_name = "Anonymous Author"
    filename = os.path.basename(image_path)
    base_name, _ = os.path.splitext(filename)
    timestamp = int(time.time() * 1000)
    wm_output_path = os.path.join(PROCESSED_DIR, f"{base_name}_{timestamp}_wm.png")
    c2pa_output_path = os.path.join(PROCESSED_DIR, f"{base_name}_{timestamp}_signed.png")
    try:
        bgr_img = cv2.imread(image_path)
        if bgr_img is None:
            return None, "❌ Không đọc được ảnh, vui lòng kiểm tra lại file!", get_history()
        h, w = bgr_img.shape[:2]
        if h < MIN_WM_SIZE or w < MIN_WM_SIZE:
            scale = MIN_WM_SIZE / min(h, w)
            new_w, new_h = int(w * scale) + 1, int(h * scale) + 1
            bgr_img = cv2.resize(bgr_img, (new_w, new_h), interpolation=cv2.INTER_CUBIC)
        encoder = WatermarkEncoder()
        encoder.set_watermark('bytes', WATERMARK_TEXT.encode('utf-8'))
        encoded_bgr = encoder.encode(bgr_img, 'dwtDctSvd')
        cv2.imwrite(wm_output_path, encoded_bgr)
        manifest = {
            "claim_generator": "C2PA_Watermark_App/1.0",
            "assertions": []
        }
        manifest["assertions"].append({
            "label": "stds.schema-org.CreativeWork",
            "data": {
                "@context": "https://schema.org",
                "@type": "CreativeWork",
                "author": [{"@type": "Person", "name": author_name}]
            }
        })
        manifest["assertions"].append({
            "label": "c2pa.actions",
            "data": {
                "actions": [{
                    "action": "c2pa.created",
                    "when": time.strftime("%Y-%m-%dT%H:%M:%SZ")
                }]
            }
        })
        builder = c2pa.Builder(manifest)
        with open("es256_certs.pem", "rb") as f:
            certs = f.read()
        with open("es256_private.key", "rb") as f:
            private_key = f.read()
        signer = c2pa.create_signer(
            lambda data: sign_es256(data, private_key),
            c2pa.SigningAlg.ES256,
            certs,
            None
        )
        builder.sign_file(signer, wm_output_path, c2pa_output_path)
        log_history(
            filename=os.path.basename(c2pa_output_path),
            action="Nhúng WM & Ký C2PA",
            c2pa_status="Thành công",
            watermark_status="Đã nhúng (DWT-DCT)",
            author=author_name,
            details=f"Đã nhúng secret '{WATERMARK_TEXT}' và ký C2PA Manifest thành công."
        )
        status_msg = f"✅ **Hoàn thành!**\n- Đã nhúng Watermark (`{WATERMARK_TEXT}`).\n- Đã ký C2PA Manifest tác giả **{author_name}**."
        return c2pa_output_path, status_msg, get_history()
    except Exception as e:
        return None, f"❌ Lỗi xử lý: {str(e)}", get_history()

def verify_image(image_path):
    if image_path is None:
        return "⚠️ Vui lòng tải ảnh cần xác minh!", get_history()
    filename = os.path.basename(image_path)
    c2pa_status, wm_status, author = "Bị thiếu / Xóa", "Chưa kiểm tra", "Không xác định"
    report = [f"### 🔍 Kết quả xác minh: `{filename}`\n"]
    c2pa_success = False
    try:
        reader = c2pa.Reader.from_file(image_path)
        manifest_store = json.loads(reader.json())
        active_key = manifest_store.get("active_manifest")
        if active_key:
            c2pa_success = True
            c2pa_status = "Hợp lệ (Success)"
            manifest_data = manifest_store["manifests"][active_key]
            try:
                author = manifest_data["assertions"][0]["data"]["author"][0]["name"]
            except Exception:
                author = "Unspecified Author"
            report.append("🟢 **[LỚP 1 - C2PA MANIFEST]: THÀNH CÔNG**")
            report.append(f"- **Tác giả:** `{author}`")
            report.append(f"- **Claim Generator:** `{manifest_data.get('claim_generator', 'N/A')}`")
            report.append(f"- **Manifest ID:** `{active_key}`")
            log_detail = "C2PA Manifest hợp lệ."
    except Exception:
        report.append("🟡 **[LỚP 1 - C2PA MANIFEST]: KHÔNG TÌM THẤY METADATA**")
        c2pa_status = "Không tồn tại / Đã bị strip"
        log_detail = "C2PA bị gỡ hoặc không tồn tại."
    if not c2pa_success:
        report.append("\n🔄 **KÍCH HOẠT CHẾ ĐỘ DỰ PHÒNG (FALLBACK)...**")
        try:
            bgr_img = cv2.imread(image_path)
            decoder = WatermarkDecoder('bytes', WATERMARK_BITS_LEN)
            extracted_bytes = decoder.decode(bgr_img, 'dwtDctSvd')
            extracted_text = extracted_bytes.decode('utf-8', errors='ignore')
            similarity = difflib.SequenceMatcher(None, extracted_text, WATERMARK_TEXT).ratio()
            if similarity >= 0.4 or WATERMARK_TEXT[:8] in extracted_text:
                wm_status = "Hợp lệ (Matched)"
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT author FROM history WHERE watermark_status LIKE ? ORDER BY timestamp DESC LIMIT 1",
                    ("%Đã nhúng%",)
                )
                result = cursor.fetchone()
                conn.close()
                if result and result[0]:
                    author = result[0]
                report.append("🟢 **[LỚP 2 - INVISIBLE WATERMARK]: THÀNH CÔNG (FALLBACK MATCH)**")
                report.append(f"- **Watermark trích xuất:** `{extracted_text}` (Độ tương đồng: {similarity*100:.1f}%)")
                report.append(f"- **Tác giả:** `{author}`")
            else:
                wm_status = "Không khớp"
                report.append("🔴 **[LỚP 2 - INVISIBLE WATERMARK]: THẤT BẠI**")
                report.append(f"- **Nội dung đọc được:** `{extracted_text}` (Độ tương đồng quá thấp: {similarity*100:.1f}%)")
        except Exception as e:
            wm_status = "Lỗi giải mã"
            report.append(f"🔴 **[LỚP 2 - INVISIBLE WATERMARK]: LỖI ({str(e)})**")
    else:
        wm_status = "Bỏ qua (C2PA đã xác thực)"
    log_history(
        filename=filename,
        action="Xác minh",
        c2pa_status=c2pa_status,
        watermark_status=wm_status,
        author=author,
        details=log_detail
    )
    return "\n".join(report), get_history()

def strip_metadata_simulation(image_path):
    if image_path is None:
        return None, "⚠️ Vui lòng chọn ảnh!", get_history()
    filename = os.path.basename(image_path)
    base_name, _ = os.path.splitext(filename)
    timestamp = int(time.time() * 1000)
    stripped_path = os.path.join(PROCESSED_DIR, f"{base_name}_{timestamp}_stripped.png")
    try:
        bgr_img = cv2.imread(image_path)
        if bgr_img is None:
            return None, "❌ Không đọc được ảnh!", get_history()
        success = cv2.imwrite(stripped_path, bgr_img)
        if not success:
            return None, "❌ Lỗi lưu file!", get_history()
        log_history(
            filename=os.path.basename(stripped_path),
            original_file=filename,
            action="Mô phỏng gỡ Metadata",
            c2pa_status="Đã bị gỡ",
            watermark_status="Còn lưu trong Pixels",
            author="Unknown",
            details="Đã xóa sạch C2PA Manifest/EXIF. Watermark vẫn giữ nguyên trong pixel data."
        )
        return stripped_path, "✅ Đã gỡ bỏ C2PA Metadata!\n⚠️ Watermark vẫn còn trong pixel data (DWT-DCT).", get_history()
    except Exception as e:
        return None, f"❌ Lỗi: {str(e)}", get_history()

with gr.Blocks(title="C2PA & Watermark Security Suite") as demo:
    gr.Markdown("# 🛡️ Hệ Thống Bảo Vệ Bản Quyền Ảnh 2 Lớp & Theo Dõi Chỉnh Sửa")
    with gr.Tabs():
        with gr.TabItem("1. Nhúng Watermark & Ký C2PA Gốc"):
            with gr.Row():
                with gr.Column():
                    img_input = gr.Image(type="filepath", label="Ảnh nguyên bản")
                    author_input = gr.Textbox(label="Tên Tác Giả", value="Trần Văn A")
                    btn_sign = gr.Button("🔒 Bảo vệ Ảnh", variant="primary")
                with gr.Column():
                    signed_img_output = gr.Image(label="Ảnh đã ký C2PA & Nhúng Watermark")
                    sign_status = gr.Markdown()
        with gr.TabItem("2. Mô Phỏng Xóa Metadata"):
            with gr.Row():
                with gr.Column():
                    strip_input = gr.Image(type="filepath", label="Ảnh đã ký C2PA")
                    btn_strip = gr.Button("✂️ Xóa Metadata C2PA", variant="stop")
                with gr.Column():
                    stripped_img_output = gr.Image(label="Ảnh đã bị xóa Metadata")
                    strip_status = gr.Markdown()
        with gr.TabItem("3. Chỉnh Sửa & Cập Nhật Manifest"):
            gr.Markdown("Xử lý ảnh khi bị sửa đổi để nối tiếp chuỗi **Chain of Custody**")
            with gr.Row():
                with gr.Column():
                    edit_orig_input = gr.Image(type="filepath", label="1. Ảnh gốc (Đã ký C2PA)")
                    edit_mod_input = gr.Image(type="filepath", label="2. Ảnh đã qua chỉnh sửa")
                    editor_input = gr.Textbox(label="Tên Người Chỉnh Sửa", value="Nguyễn Văn B")
                    edit_type_input = gr.Dropdown(
                        choices=["crop", "rotate", "filter", "color_adjust", "resize", "other"],
                        value="crop", label="Loại Chỉnh Sửa"
                    )
                    edit_desc_input = gr.Textbox(label="Mô Tả Chi Tiết", value="Cắt nhỏ bối cảnh và tăng độ tương phản")
                    btn_process_edit = gr.Button("🔄 Ký C2PA Cho Ảnh Đã Sửa", variant="primary")
                with gr.Column():
                    edited_signed_output = gr.Image(label="Ảnh đã chỉnh sửa (Signed C2PA)")
                    edit_status = gr.Markdown()
        with gr.TabItem("4. Xác Minh Bản Quyền (Fallback)"):
            with gr.Row():
                with gr.Column():
                    verify_input = gr.Image(type="filepath", label="Ảnh cần xác minh")
                    btn_verify = gr.Button("🔍 Kiểm Tra 2 Lớp", variant="primary")
                with gr.Column():
                    verify_report = gr.Markdown()
        with gr.TabItem("5. Chuỗi Chỉnh Sửa & Manifest"):
            gr.Markdown("Xem toàn bộ lịch sử thay đổi của ảnh từ C2PA Manifest")
            with gr.Row():
                with gr.Column():
                    chain_input_img = gr.Image(type="filepath", label="Tải ảnh để xem chuỗi chỉnh sửa")
                    btn_trace = gr.Button("🔗 Xem Chuỗi Chỉnh Sửa", variant="primary")
                with gr.Column():
                    chain_report = gr.HTML(label="Chuỗi chỉnh sửa")
        with gr.TabItem("6. Lịch Sử Hệ Thống (Database)"):
            history_table = gr.HTML(value=get_history())
            btn_refresh_hist = gr.Button("🔄 Làm Mới Lịch Sử")
    btn_sign.click(
        fn=process_and_sign,
        inputs=[img_input, author_input],
        outputs=[signed_img_output, sign_status, history_table]
    )
    btn_strip.click(
        fn=strip_metadata_simulation,
        inputs=[strip_input],
        outputs=[stripped_img_output, strip_status, history_table]
    )
    btn_process_edit.click(
        fn=process_edited_image_with_c2pa,
        inputs=[edit_orig_input, edit_mod_input, editor_input, edit_type_input, edit_desc_input],
        outputs=[edited_signed_output, edit_status, history_table]
    )
    btn_verify.click(
        fn=verify_image,
        inputs=[verify_input],
        outputs=[verify_report, history_table]
    )
    btn_trace.click(
        fn=trace_edit_chain,
        inputs=[chain_input_img],
        outputs=[chain_report]
    )
    btn_refresh_hist.click(
        fn=get_history,
        inputs=[],
        outputs=[history_table]
    )

if __name__ == "__main__":
    demo.launch()