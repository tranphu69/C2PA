import os
import json
import time
import html
import zlib
import struct
import secrets
import mimetypes
import sqlite3
import difflib
from datetime import datetime, timezone
import cv2
import gradio as gr
import c2pa
from imwatermark import WatermarkEncoder, WatermarkDecoder
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cert_manager import (
    ROOT_CERT_PATH,
    list_authors,
    author_paths,
    load_signing_material,
    get_cert_info,
)
from trust_list_enhancement import (
    init_trust_list_db,
    add_to_trust_list,
    revoke_from_trust_list,
    find_trust_entry,
    get_trust_list,
    log_verification_audit,
    get_verification_audit_log,
    VERDICT_LABELS,
)

BASE_DIR = "c2pa_watermark_app"
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
PROCESSED_DIR = os.path.join(BASE_DIR, "processed")
DB_PATH = os.path.join(BASE_DIR, "history.db")
MIN_WM_SIZE = 256
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(PROCESSED_DIR, exist_ok=True)
WM_CODE_HEX_LEN = 16
WATERMARK_BITS_LEN = WM_CODE_HEX_LEN * 8
APP_AGENT = "C2PA_Watermark_App/1.0"
TSA_URL = None
DIGITAL_SOURCE_TYPE = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture"
EDIT_ACTION_MAP = {
    "crop": "c2pa.cropped",
    "rotate": "c2pa.orientation",
    "filter": "c2pa.filtered",
    "color_adjust": "c2pa.color_adjustments",
    "resize": "c2pa.resized",
    "other": "c2pa.edited",
}

if not os.path.exists(ROOT_CERT_PATH):
    raise FileNotFoundError(
        "Chưa có Root CA và chứng chỉ tác giả!\nChạy: python 01_generate_certificate.py"
    )

def esc(value) -> str:
    return html.escape(str(value), quote=True)

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def generate_watermark_code() -> str:
    return secrets.token_hex(WM_CODE_HEX_LEN // 2)

def guess_mime_type(path):
    mime, _ = mimetypes.guess_type(path)
    return mime or "image/png"

def sign_es256(data: bytes, private_key_pem: bytes) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=None, backend=default_backend()
    )
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Private key không phải là EC (Elliptic Curve) key hợp lệ cho ES256!")
    return private_key.sign(data, ec.ECDSA(hashes.SHA256()))

def make_signer(author_name):
    chain_pem, key_pem = load_signing_material(author_name)
    signer = c2pa.create_signer(
        lambda data: sign_es256(data, key_pem),
        c2pa.SigningAlg.ES256,
        chain_pem,
        TSA_URL,
    )
    return signer, get_cert_info(chain_pem)

def get_author_names():
    return [a["name"] for a in list_authors()]

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
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS watermark_registry (
            code TEXT PRIMARY KEY,
            image_filename TEXT,
            author TEXT,
            created_timestamp TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()
init_trust_list_db()

def log_history(filename, action, c2pa_status, watermark_status, author, details,
                original_file=None, edit_type=None, edit_details=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO history
        (timestamp, filename, original_file, action, c2pa_status, watermark_status, author, details, edit_type, edit_details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, filename, original_file, action, c2pa_status, watermark_status,
          author, details, edit_type, edit_details))
    conn.commit()
    conn.close()

def register_watermark_code(code, image_filename, author):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT OR REPLACE INTO watermark_registry (code, image_filename, author, created_timestamp)
        VALUES (?, ?, ?, ?)
    """, (code, image_filename, author, timestamp))
    conn.commit()
    conn.close()

def lookup_author_by_watermark_code(extracted_code, similarity_threshold=0.85):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT author, code FROM watermark_registry WHERE code = ?", (extracted_code,))
    row = cursor.fetchone()
    if row:
        conn.close()
        return row[0], row[1], 1.0
    cursor.execute("SELECT author, code FROM watermark_registry")
    all_rows = cursor.fetchall()
    conn.close()
    best_author, best_code, best_ratio = None, None, 0.0
    for author, code in all_rows:
        ratio = difflib.SequenceMatcher(None, extracted_code, code).ratio()
        if ratio > best_ratio:
            best_author, best_code, best_ratio = author, code, ratio
    if best_ratio >= similarity_threshold:
        return best_author, best_code, best_ratio
    return None, None, best_ratio

def _c2pa_status_color(text):
    t = text or ""
    if any(k in t for k in ("Bị chỉnh sửa", "Lỗi", "hỏng")):
        return "#dc3545"
    if "chưa được công nhận" in t:
        return "#e67e22"
    if any(k in t for k in ("Tin cậy", "Thành công", "Hợp lệ")):
        return "#28a745"
    return "#6c757d"

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
    out = """
    <table style="width:100%; border-collapse: collapse; text-align: left; font-size: 13px;">
    <tr style="background-color: #f2f2f2; border-bottom: 2px solid #ddd;">
        <th style="padding: 8px;">ID</th><th style="padding: 8px;">Thời gian</th>
        <th style="padding: 8px;">File</th><th style="padding: 8px;">File gốc</th>
        <th style="padding: 8px;">Hành động</th><th style="padding: 8px;">C2PA Status</th>
        <th style="padding: 8px;">Watermark</th><th style="padding: 8px;">Tác giả/Người sửa</th>
        <th style="padding: 8px;">Loại sửa</th><th style="padding: 8px;">Chi tiết</th>
    </tr>
    """
    for r in rows:
        wm_col = r[6] or ""
        wm_color = ("#28a745" if any(k in wm_col for k in ("Hợp lệ", "Thành công", "Đã nhúng"))
                    else "#dc3545" if any(k in wm_col for k in ("Không khớp", "Thất bại", "Lỗi"))
                    else "#6c757d")
        out += f"""
        <tr style="border-bottom: 1px solid #eee;">
            <td style="padding: 8px;">{r[0]}</td>
            <td style="padding: 8px;">{esc(r[1])}</td>
            <td style="padding: 8px;"><b>{esc(r[2])}</b></td>
            <td style="padding: 8px;">{esc(r[3]) if r[3] else '-'}</td>
            <td style="padding: 8px;">{esc(r[4])}</td>
            <td style="padding: 8px; color: {_c2pa_status_color(r[5])}; font-weight: bold;">{esc(r[5])}</td>
            <td style="padding: 8px; color: {wm_color}; font-weight: bold;">{esc(r[6])}</td>
            <td style="padding: 8px;">{esc(r[7]) if r[7] else '-'}</td>
            <td style="padding: 8px;">{esc(r[8]) if r[8] else '-'}</td>
            <td style="padding: 8px;">{esc(r[9])}</td>
        </tr>
        """
    return out + "</table>"

TRUST_INFO_CODES = {"signingCredential.untrusted", "timeStamp.untrusted"}
EXPIRY_CODES = {
    "signingCredential.expired",
    "claimSignature.outsideValidity",
    "timeStamp.outsideValidity",
}
SUCCESS_SUFFIXES = (".match", ".validated", ".trusted", ".insideValidity", ".notRevoked")

def _is_success_code(code, item):
    if item.get("success") is True:
        return True
    return code.endswith(SUCCESS_SUFFIXES)

def extract_validation(container):
    failures, successes, seen = [], [], set()
    def add(items):
        for it in items or []:
            if not isinstance(it, dict) or not it.get("code"):
                continue
            code = it["code"]
            key = (code, it.get("url"))
            if key in seen:
                continue
            seen.add(key)
            target = successes if _is_success_code(code, it) else failures
            target.append((code, it.get("explanation") or ""))
    add(container.get("validation_status"))
    active = (container.get("validation_results") or {}).get("activeManifest") or {}
    for bucket in ("failure", "success", "informational"):
        add(active.get(bucket))
    return failures, successes

def _is_no_manifest_error(exc) -> bool:
    text = f"{type(exc).__name__} {exc}".lower()
    return any(k in text for k in ("manifestnotfound", "no manifest", "jumbf"))

def get_claimed_author(manifest_data):
    for assertion in manifest_data.get("assertions", []):
        if "CreativeWork" in assertion.get("label", ""):
            authors = (assertion.get("data") or {}).get("author") or []
            if authors and isinstance(authors, list) and isinstance(authors[0], dict):
                return authors[0].get("name")
    return None

def resolve_signer(manifest_data):
    sig = manifest_data.get("signature_info") or {}
    serial = sig.get("cert_serial_number")
    claimed = get_claimed_author(manifest_data)
    entry = find_trust_entry(serial)
    if entry is None:
        state = "unknown"
    elif entry["is_approved"]:
        state = "trusted"
    else:
        state = "revoked"
    norm = lambda s: (s or "").strip().casefold()
    name_mismatch = bool(entry and claimed and norm(claimed) != norm(entry["author_name"]))
    display = entry["author_name"] if entry else (claimed or "Không xác định")
    return {
        "serial": serial,
        "issuer": sig.get("issuer"),
        "alg": sig.get("alg"),
        "time": sig.get("time"),
        "claimed": claimed,
        "entry": entry,
        "state": state,
        "name_mismatch": name_mismatch,
        "display_name": display,
    }

def analyze_credentials(image_path):
    res = {
        "verdict": "NO_CREDENTIALS", "label": None, "manifest": None, "signer": None,
        "integrity": [], "warnings": [], "infos": [], "successes": [],
        "state": None, "note": None, "error": None,
    }
    try:
        reader = c2pa.Reader.from_file(image_path)
        store = json.loads(reader.json())
    except Exception as e:
        if _is_no_manifest_error(e):
            return res
        res.update(verdict="ERROR", error=f"{type(e).__name__}: {e}")
        return res
    label = store.get("active_manifest")
    manifests = store.get("manifests") or {}
    if not label or label not in manifests:
        return res
    manifest = manifests[label]
    res.update(label=label, manifest=manifest, state=store.get("validation_state"))
    failures, successes = extract_validation(store)
    res["successes"] = [c for c, _ in successes]
    for code, explanation in failures:
        if code in TRUST_INFO_CODES:
            res["infos"].append((code, explanation))
        elif code in EXPIRY_CODES or code.startswith("assertion.action."):
            res["warnings"].append((code, explanation))
        else:
            res["integrity"].append((code, explanation))   # hash/chữ ký không khớp, thiếu assertion...
    signer = resolve_signer(manifest)
    res["signer"] = signer
    if res["integrity"]:
        res["verdict"] = "TAMPERED"
    elif signer["state"] == "trusted" and not signer["name_mismatch"]:
        res["verdict"] = "TRUSTED"
    else:
        res["verdict"] = "UNKNOWN_SIGNER"
        if signer["name_mismatch"]:
            res["note"] = (f"Tên tác giả tự khai trong manifest ('{signer['claimed']}') khác danh tính "
                           f"trong chứng chỉ ('{signer['entry']['author_name']}').")
    return res

VERDICT_BANNERS = {
    "TRUSTED": "## 🟢 TIN CẬY\nNội dung khớp chữ ký C2PA và người ký nằm trong Trust List.",
    "UNKNOWN_SIGNER": ("## 🟡 HỢP LỆ NHƯNG NGƯỜI KÝ CHƯA ĐƯỢC CÔNG NHẬN\n"
                       "Nội dung không bị sửa sau khi ký, nhưng không thể xác nhận người ký là ai."),
    "TAMPERED": ("## 🔴 NGHI VẤN: ẢNH HOẶC MANIFEST ĐÃ BỊ THAY ĐỔI\n"
                 "Hash nội dung hoặc chữ ký không còn khớp với ảnh hiện tại."),
    "NO_CREDENTIALS": ("## ⚪ KHÔNG CÓ CONTENT CREDENTIALS\n"
                       "Điều này **không có nghĩa là ảnh giả**, chỉ là không xác định được nguồn gốc bằng C2PA."),
    "ERROR": "## 🟣 KHÔNG THỂ KẾT LUẬN\nGặp lỗi khi đọc Content Credentials.",
}
C2PA_STATUS_TEXT = {
    "TRUSTED": "Tin cậy: hợp lệ + người ký trong Trust List",
    "UNKNOWN_SIGNER": "Hợp lệ nhưng người ký chưa được công nhận",
    "TAMPERED": "Bị chỉnh sửa / chữ ký hỏng",
    "NO_CREDENTIALS": "Không có Content Credentials",
    "ERROR": "Lỗi đọc manifest",
}

def process_and_sign(image_path, author_name):
    if image_path is None:
        return None, "⚠️ Vui lòng tải ảnh lên trước!", get_history()
    if not author_name:
        return None, "⚠️ Vui lòng chọn danh tính người ký (tạo bằng 01_generate_certificate.py).", get_history()
    filename = os.path.basename(image_path)
    base_name, _ = os.path.splitext(filename)
    timestamp = int(time.time() * 1000)
    wm_output_path = os.path.join(PROCESSED_DIR, f"{base_name}_{timestamp}_wm.png")
    c2pa_output_path = os.path.join(PROCESSED_DIR, f"{base_name}_{timestamp}_signed.png")
    try:
        signer, cert_info = make_signer(author_name)
        signer_name = cert_info["cn"]
        bgr_img = cv2.imread(image_path)
        if bgr_img is None:
            return None, "❌ Không đọc được ảnh, vui lòng kiểm tra lại file!", get_history()
        h, w = bgr_img.shape[:2]
        if h < MIN_WM_SIZE or w < MIN_WM_SIZE:
            scale = MIN_WM_SIZE / min(h, w)
            bgr_img = cv2.resize(bgr_img, (int(w * scale) + 1, int(h * scale) + 1),
                                 interpolation=cv2.INTER_CUBIC)
        watermark_code = generate_watermark_code()
        encoder = WatermarkEncoder()
        encoder.set_watermark("bytes", watermark_code.encode("utf-8"))
        encoded_bgr = encoder.encode(bgr_img, "dwtDctSvd")
        cv2.imwrite(wm_output_path, encoded_bgr)
        manifest = {
            "claim_generator": APP_AGENT,
            "assertions": [
                {
                    "label": "stds.schema-org.CreativeWork",
                    "data": {
                        "@context": "https://schema.org",
                        "@type": "CreativeWork",
                        "author": [{"@type": "Person", "name": signer_name}],
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
        builder = c2pa.Builder(manifest)
        builder.sign_file(signer, wm_output_path, c2pa_output_path)
        register_watermark_code(code=watermark_code,
                                image_filename=os.path.basename(c2pa_output_path),
                                author=signer_name)
        entry = find_trust_entry(cert_info["serial"])
        if entry and entry["is_approved"]:
            trust_msg = "✅ Chứng chỉ của người ký **đã có** trong Trust List."
        else:
            trust_msg = "⚠️ Chứng chỉ của người ký **chưa có** trong Trust List (vào tab 8 để phê duyệt). Khi xác minh ảnh sẽ ở mức 'người ký chưa được công nhận'."
        log_history(
            filename=os.path.basename(c2pa_output_path),
            action="Nhúng WM & Ký C2PA",
            c2pa_status="Thành công",
            watermark_status=f"Đã nhúng (DWT-DCT), mã: {watermark_code}",
            author=signer_name,
            details=f"Ký bằng chứng chỉ serial {cert_info['serial'][:12]}... (Root CA -> leaf).",
        )
        status_msg = (
            f"✅ **Hoàn thành!**\n"
            f"- Đã nhúng Watermark riêng cho ảnh này (mã: `{watermark_code}`).\n"
            f"- Đã ký C2PA Manifest bằng chứng chỉ của **{esc(signer_name)}** ({esc(cert_info['org'])}).\n"
            f"- {trust_msg}"
        )
        return c2pa_output_path, status_msg, get_history()
    except Exception as e:
        return None, f"❌ Lỗi xử lý: {esc(e)}", get_history()

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
        if not cv2.imwrite(stripped_path, bgr_img):
            return None, "❌ Lỗi lưu file!", get_history()
        log_history(
            filename=os.path.basename(stripped_path),
            original_file=filename,
            action="Mô phỏng gỡ Metadata",
            c2pa_status="Đã bị gỡ",
            watermark_status="Còn lưu trong Pixels",
            author="Unknown",
            details="Đã xóa sạch C2PA Manifest/EXIF. Watermark vẫn giữ nguyên trong pixel data.",
        )
        return stripped_path, "✅ Đã gỡ bỏ C2PA Metadata!\n⚠️ Watermark vẫn còn trong pixel data (DWT-DCT).", get_history()
    except Exception as e:
        return None, f"❌ Lỗi: {esc(e)}", get_history()

def tamper_pixels_keep_manifest(file_path):
    if file_path is None:
        return None, "⚠️ Vui lòng chọn file PNG đã ký!", get_history()
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if data[:8] != b"\x89PNG\r\n\x1a\n":
            return None, "❌ Chức năng này chỉ hỗ trợ PNG (ảnh do tab 1/3 tạo ra là PNG).", get_history()
        chunks, pos = [], 8
        while pos + 8 <= len(data):
            length = struct.unpack(">I", data[pos:pos + 4])[0]
            ctype = data[pos + 4:pos + 8]
            chunks.append((ctype, data[pos + 8:pos + 8 + length]))
            pos += 12 + length
            if ctype == b"IEND":
                break
        ihdr = next(body for t, body in chunks if t == b"IHDR")
        width, height, bit_depth, color_type, _, _, interlace = struct.unpack(">IIBBBBB", ihdr)
        if interlace:
            return None, "❌ Không hỗ trợ PNG interlaced.", get_history()
        channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}[color_type]
        stride = 1 + (width * channels * bit_depth + 7) // 8
        raw = bytearray(zlib.decompress(b"".join(b for t, b in chunks if t == b"IDAT")))
        start_row = height // 2
        for r in range(start_row, min(start_row + 24, height)):
            for i in range(min(160, stride - 1)):
                raw[r * stride + 1 + i] = (raw[r * stride + 1 + i] + 128) & 0xFF
        new_idat = zlib.compress(bytes(raw), 6)
        out = bytearray(b"\x89PNG\r\n\x1a\n")
        idat_done = False
        for ctype, body in chunks:
            if ctype == b"IDAT":
                if idat_done:
                    continue
                body, idat_done = new_idat, True
            out += struct.pack(">I", len(body)) + ctype + body
            out += struct.pack(">I", zlib.crc32(ctype + body) & 0xFFFFFFFF)
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        out_path = os.path.join(PROCESSED_DIR, f"{base_name}_{int(time.time() * 1000)}_tampered.png")
        with open(out_path, "wb") as f:
            f.write(out)
        log_history(
            filename=os.path.basename(out_path),
            original_file=os.path.basename(file_path),
            action="Mô phỏng sửa pixel (giữ manifest)",
            c2pa_status="Manifest còn nguyên nhưng nội dung đã đổi",
            watermark_status="Có thể bị ảnh hưởng",
            author="Attacker",
            details="Đổi dữ liệu điểm ảnh, giữ chunk C2PA. Kỳ vọng: xác minh báo dataHash.mismatch.",
        )
        return out_path, ("✅ Đã sửa pixel nhưng vẫn giữ manifest.\n"
                          "➡️ Tải file này sang tab 4 để xem hệ thống phát hiện bị chỉnh sửa."), get_history()
    except Exception as e:
        return None, f"❌ Lỗi: {esc(e)}", get_history()

def build_edit_manifest(editor_name, edit_type, edit_description):
    now = utc_now_iso()
    return {
        "claim_generator": APP_AGENT,
        "assertions": [
            {
                "label": "stds.schema-org.CreativeWork",
                "data": {
                    "@context": "https://schema.org",
                    "@type": "CreativeWork",
                    "author": [{"@type": "Person", "name": editor_name}],
                },
            },
            {
                "label": "c2pa.actions",
                "data": {
                    "actions": [
                        {"action": "c2pa.opened", "when": now, "softwareAgent": APP_AGENT},
                        {
                            "action": EDIT_ACTION_MAP.get(edit_type, "c2pa.edited"),
                            "when": now,
                            "softwareAgent": APP_AGENT,
                            "parameters": {"name": edit_type, "description": edit_description},
                        },
                    ]
                },
            },
        ],
    }

def process_edited_image_with_c2pa(original_image_path, edited_image_path, editor_name, edit_type, edit_description):
    if original_image_path is None or edited_image_path is None:
        return None, "⚠️ Vui lòng cung cấp đầy đủ ảnh gốc và ảnh đã chỉnh sửa!", get_history()
    if not editor_name:
        return None, "⚠️ Vui lòng chọn danh tính người chỉnh sửa (tạo bằng 01_generate_certificate.py).", get_history()
    try:
        parent = analyze_credentials(original_image_path)
        signer, cert_info = make_signer(editor_name)
        editor_cn = cert_info["cn"]
        manifest = build_edit_manifest(editor_cn, edit_type, edit_description)
        ext = os.path.splitext(edited_image_path)[1] or ".png"
        base_name = os.path.splitext(os.path.basename(edited_image_path))[0]
        out_path = os.path.join(PROCESSED_DIR, f"{base_name}_{int(time.time() * 1000)}_edited_signed{ext}")
        builder = c2pa.Builder(manifest)
        ingredient_json = {
            "title": os.path.basename(original_image_path),
            "format": guess_mime_type(original_image_path),
            "relationship": "parentOf",
        }
        with open(original_image_path, "rb") as ingredient_stream:
            builder.add_ingredient(
                json.dumps(ingredient_json),
                guess_mime_type(original_image_path),
                ingredient_stream,
            )
        builder.sign_file(signer, edited_image_path, out_path)
        log_history(
            filename=os.path.basename(out_path),
            original_file=os.path.basename(original_image_path),
            action="Chỉnh sửa ảnh",
            c2pa_status="Thành công: manifest chỉnh sửa (ingredient parentOf)",
            watermark_status="Watermark giữ nguyên (nếu không bị phá vỡ bởi phép sửa)",
            author=editor_cn,
            details=f"{EDIT_ACTION_MAP.get(edit_type, 'c2pa.edited')}: {edit_description}",
            edit_type=edit_type,
            edit_details=edit_description,
        )
        msg = (f"✅ Ảnh chỉnh sửa đã được ký bởi **{esc(editor_cn)}** và liên kết provenance với ảnh gốc.\n"
               f"- Hành động chuẩn: `c2pa.opened` → `{EDIT_ACTION_MAP.get(edit_type, 'c2pa.edited')}`\n"
               f"- File mới: `{esc(out_path)}`")
        if parent["verdict"] != "TRUSTED":
            msg += (f"\n\n⚠️ Lưu ý: ảnh gốc đang ở mức **{VERDICT_LABELS[parent['verdict']][0]}**, "
                    f"nên chuỗi provenance mới cũng kế thừa mức tin cậy đó.")
        return out_path, msg, get_history()
    except Exception as e:
        return None, f"❌ Lỗi khi ký C2PA: {esc(e)}", get_history()

def verify_image(image_path):
    if image_path is None:
        return "⚠️ Vui lòng tải ảnh cần xác minh!", get_history()
    filename = os.path.basename(image_path)
    a = analyze_credentials(image_path)
    verdict, signer = a["verdict"], a["signer"]
    author, wm_status = "Không xác định", "Chưa kiểm tra"
    report = [f"### 🔍 Kết quả xác minh: `{esc(filename)}`\n", VERDICT_BANNERS[verdict], ""]
    if verdict == "ERROR":
        report.append(f"- Chi tiết lỗi: `{esc(a['error'])}`")
    if signer:
        author = signer["display_name"]
        report.append("#### 🔐 Người ký (đọc từ chứng chỉ trong manifest)")
        report.append(f"- **Serial chứng chỉ:** `{esc(signer['serial'] or 'không đọc được')}`")
        report.append(f"- **Tổ chức của người ký:** `{esc(signer['issuer'] or 'N/A')}`")
        report.append(f"- **Thuật toán / thời điểm ký:** `{esc(signer['alg'] or 'N/A')}` / "
                      f"`{esc(signer['time'] or 'không có (chưa cấu hình TSA)')}`")
        if signer["state"] == "trusted":
            e = signer["entry"]
            report.append(f"- **Trust List:** ✅ đã phê duyệt: **{esc(e['author_name'])}** ({esc(e['organization'] or '-')})")
        elif signer["state"] == "revoked":
            report.append(f"- **Trust List:** ⛔ chứng chỉ đã bị thu hồi lúc {esc(signer['entry']['revoked_timestamp'])}")
        else:
            report.append("- **Trust List:** ⚠️ chứng chỉ này chưa được phê duyệt")
        if signer["claimed"]:
            suffix = "" if signer["state"] == "trusted" else " *(tự khai, chưa được chứng thực)*"
            report.append(f"- **Tác giả tự khai trong manifest:** `{esc(signer['claimed'])}`{suffix}")
        if a["note"]:
            report.append(f"- ⚠️ {esc(a['note'])}")
        report.append(f"- **Claim generator:** `{esc(a['manifest'].get('claim_generator', 'N/A'))}`")
        report.append(f"- **Manifest ID:** `{esc(a['label'])}`")
        report.append("\n#### 🧪 Kiểm tra toàn vẹn (validation_status)")
        if a["state"]:
            report.append(f"- **validation_state:** `{esc(a['state'])}`")
        if a["integrity"]:
            for code, expl in a["integrity"]:
                report.append(f"- 🔴 `{esc(code)}` {esc(expl)}")
        else:
            report.append("- 🟢 Không phát hiện lỗi toàn vẹn (hash nội dung và chữ ký khớp).")
        for code, expl in a["warnings"]:
            report.append(f"- 🟠 Cảnh báo `{esc(code)}` {esc(expl)}")
        for code, expl in a["infos"]:
            report.append(f"- ℹ️ `{esc(code)}`: Root CA demo không nằm trong danh sách tin cậy công khai của C2PA (bình thường với chứng chỉ demo).")
    c2pa_status = C2PA_STATUS_TEXT[verdict]
    log_detail = c2pa_status
    if verdict == "NO_CREDENTIALS":
        report.append("\n🔄 **Kích hoạt lớp 2: giải mã Invisible Watermark...**")
        try:
            bgr_img = cv2.imread(image_path)
            if bgr_img is None:
                raise ValueError("Không đọc được ảnh")
            decoder = WatermarkDecoder("bytes", WATERMARK_BITS_LEN)
            extracted_code = decoder.decode(bgr_img, "dwtDctSvd").decode("utf-8", errors="ignore")
            matched_author, _, similarity = lookup_author_by_watermark_code(extracted_code)
            if matched_author is not None:
                wm_status = "Hợp lệ (Matched)"
                author = matched_author
                report.append("🟢 **[LỚP 2 - WATERMARK]: tìm thấy trong registry**")
                report.append(f"- **Mã watermark:** `{esc(extracted_code)}`")
                report.append(f"- **Nguồn gốc gợi ý:** `{esc(author)}` (độ tương đồng {similarity * 100:.1f}%)")
                report.append("- ℹ️ Đây chỉ là **gợi ý nguồn gốc** tra từ registry của hệ thống, không phải bằng chứng mật mã như chữ ký C2PA.")
                log_detail += f" | Watermark gợi ý tác giả: {author}"
            else:
                wm_status = "Không khớp"
                report.append("🔴 **[LỚP 2 - WATERMARK]: không khớp ảnh nào đã đăng ký**")
                report.append(f"- **Mã đọc được:** `{esc(extracted_code)}`")
        except Exception as e:
            wm_status = "Lỗi giải mã"
            report.append(f"🔴 **[LỚP 2 - WATERMARK]: LỖI ({esc(e)})**")
    else:
        wm_status = "Bỏ qua (đã có Content Credentials)"
    log_verification_audit(
        image_filename=filename,
        cert_serial=(signer or {}).get("serial") or "unknown",
        author_name=author,
        verdict=verdict,
        detail=log_detail,
    )
    log_history(
        filename=filename,
        action="Xác minh",
        c2pa_status=c2pa_status,
        watermark_status=wm_status,
        author=author,
        details=log_detail,
    )
    return "\n".join(report), get_history()

CARD_STYLE = ("border-left: 4px solid {color}; padding: 10px 14px; margin: 8px 0 8px {margin}px; "
              "background-color: #1e1e1e; border-radius: 4px; color: #e0e0e0; font-family: sans-serif;")

def _render_manifest(label, manifests, depth, parts, visited):
    margin = depth * 28
    if label in visited:
        parts.append(f"<div style='margin-left:{margin}px; color:#ff6b6b;'>⚠️ Phát hiện vòng lặp tại <code>{esc(label)}</code></div>")
        return
    visited.add(label)
    m = manifests.get(label)
    if m is None:
        parts.append(f"<div style='margin-left:{margin}px; color:#ff6b6b;'>⚠️ Manifest cha <code>{esc(label)}</code> không có trong file (chuỗi bị đứt).</div>")
        return
    signer = resolve_signer(m)
    if signer["state"] == "trusted":
        badge, badge_color = "✅ Trong Trust List", "#00b894"
    elif signer["state"] == "revoked":
        badge, badge_color = "⛔ Chứng chỉ đã thu hồi", "#d63031"
    else:
        badge, badge_color = "⚠️ Chưa được công nhận", "#e67e22"
    role = "Manifest hiện tại (mới nhất)" if depth == 0 else f"Manifest tổ tiên #{depth}"
    parts.append(f"""
    <div style='{CARD_STYLE.format(color="#00bfff", margin=margin)}'>
        <b style='color:#5bc0de;'>📌 {role}</b> <code style='font-size:11px;'>{esc(label)}</code><br>
        👤 <b>Người ký:</b> {esc(signer['display_name'])}
        <span style='color:{badge_color}; font-weight:bold;'>[{badge}]</span><br>
        🔏 <b>Serial chứng chỉ:</b> <code style='font-size:11px;'>{esc(str(signer['serial'] or 'N/A')[:24])}</code>
        &nbsp;🕒 <b>Dấu thời gian TSA:</b> {esc(signer['time'] or 'không có')}<br>
        🛠️ <b>Claim generator:</b> {esc(m.get('claim_generator', 'N/A'))}
    </div>
    """)
    for assertion in m.get("assertions", []):
        if not assertion.get("label", "").startswith("c2pa.actions"):
            continue
        for i, act in enumerate((assertion.get("data") or {}).get("actions", []), 1):
            action_type = act.get("action", "N/A")
            params = act.get("parameters") or {}
            body = f"<b style='color:#00ff00;'>Hành động #{i}:</b> <code style='color:#ff79c6;'>{esc(action_type)}</code><br>"
            if action_type == "c2pa.created":
                body += f"🌱 <i style='color:#ffaa00;'>Khởi tạo nội dung gốc bởi:</i> <b>{esc(signer['display_name'])}</b><br>"
                if act.get("digitalSourceType"):
                    body += f"🏷️ <b>Nguồn:</b> <code style='font-size:11px;'>{esc(str(act['digitalSourceType']).rsplit('/', 1)[-1])}</code><br>"
            elif action_type == "c2pa.opened":
                body += "📂 <i>Mở ảnh cha để chỉnh sửa (liên kết ingredient bên dưới)</i><br>"
            else:
                body += f"👤 <b style='color:#ff6b6b;'>Người thực hiện:</b> {esc(signer['display_name'])}<br>"
                if params.get("name"):
                    body += f"🏷️ <b style='color:#ff6b6b;'>Loại chỉnh sửa:</b> {esc(params['name'])}<br>"
                if params.get("description"):
                    body += f"💬 <b style='color:#ff6b6b;'>Mô tả:</b> {esc(params['description'])}<br>"
            body += f"🕒 <b>Thời gian:</b> {esc(act.get('when', 'N/A'))}"
            parts.append(f"<div style='{CARD_STYLE.format(color='#ff6b6b', margin=margin + 16)}'>{body}</div>")
    for ing in m.get("ingredients", []):
        parent_label = ing.get("active_manifest")
        fails, _ = extract_validation(ing)
        fails = [c for c, _ in fails if c not in TRUST_INFO_CODES]
        warn = (f"<br>🔴 <b>Ingredient có lỗi xác thực:</b> <code>{esc(', '.join(fails))}</code>" if fails else "")
        link = (f"Manifest cha: <code style='font-size:11px;'>{esc(parent_label)}</code>" if parent_label
                else "<i>Ảnh cha không có Content Credentials (điểm đầu của chuỗi có thể kiểm chứng)</i>")
        parts.append(f"""
        <div style='{CARD_STYLE.format(color="#9b59b6", margin=margin + 16)}'>
            🔗 <b style='color:#c792ea;'>Ingredient (ảnh cha):</b> {esc(ing.get('title', 'N/A'))}<br>
            ↳ <b>Quan hệ:</b> {esc(ing.get('relationship', 'N/A'))}<br>
            ↳ {link}{warn}
        </div>
        """)
        if parent_label:
            _render_manifest(parent_label, manifests, depth + 1, parts, visited)

def trace_edit_chain(image_path):
    if image_path is None:
        return "<p style='color: orange;'>⚠️ Vui lòng tải ảnh lên để kiểm tra chuỗi chỉnh sửa.</p>"
    try:
        try:
            reader = c2pa.Reader.from_file(image_path)
            store = json.loads(reader.json())
        except Exception as e:
            if _is_no_manifest_error(e):
                return "<p style='color: red;'>❌ Không tìm thấy C2PA Manifest trong file ảnh!</p>"
            raise
        active = store.get("active_manifest")
        manifests = store.get("manifests") or {}
        if not active or active not in manifests:
            return "<p style='color: red;'>❌ Không tìm thấy C2PA Manifest trong file ảnh!</p>"
        parts = ["<h3 style='color: #00bfff;'>📝 Chuỗi Chỉnh Sửa & Khai Báo (Chain of Custody)</h3>"]
        _render_manifest(active, manifests, 0, parts, set())
        return "".join(parts)
    except Exception as e:
        return f"<p style='color: red;'>❌ Không thể đọc chuỗi chỉnh sửa C2PA: {esc(e)}</p>"

def get_image_metadata(image_path):
    if image_path is None:
        return "<p style='color: orange;'>⚠️ Vui lòng tải ảnh lên!</p>"
    try:
        filename = os.path.basename(image_path)
        file_size_mb = os.path.getsize(image_path) / (1024 * 1024)
        out = f"""
        <div style='background: #1a1a1a; padding: 20px; border-radius: 8px; font-family: monospace; color: #e0e0e0;'>
        <h3 style='color: #fff; margin-top: 0;'>📋 METADATA ẢNH</h3>
        <div style='background: #2a2a2a; padding: 15px; margin: 10px 0; border-left: 4px solid #007bff; border-radius: 4px;'>
            <b style='color: #00bfff;'>📁 Thông tin cơ bản</b><br>
            <table style='width: 100%; margin-top: 10px; font-size: 12px; color: #e0e0e0;'>
                <tr><td><b>Tên file:</b></td><td style='color: #28a745;'>{esc(filename)}</td></tr>
                <tr><td><b>Kích thước:</b></td><td>{file_size_mb:.2f} MB</td></tr>
            </table>
        </div>
        """
        try:
            bgr_img = cv2.imread(image_path)
            if bgr_img is not None:
                height, width = bgr_img.shape[:2]
                channels = bgr_img.shape[2] if len(bgr_img.shape) > 2 else 1
                color_mode = "BGR" if channels == 3 else ("BGRA" if channels == 4 else "Grayscale")
                out += f"""
                <div style='background: #2a2a2a; padding: 15px; margin: 10px 0; border-left: 4px solid #28a745; border-radius: 4px;'>
                    <b style='color: #28a745;'>🖼️ Thông tin ảnh</b><br>
                    <table style='width: 100%; margin-top: 10px; font-size: 12px; color: #e0e0e0;'>
                        <tr><td><b>Kích thước:</b></td><td>{width}px × {height}px</td></tr>
                        <tr><td><b>Chế độ màu:</b></td><td>{color_mode}</td></tr>
                        <tr><td><b>Số kênh:</b></td><td>{channels}</td></tr>
                    </table>
                </div>
                """
        except Exception:
            pass
        return out + "</div>"
    except Exception as e:
        return f"<p style='color: red;'>❌ Lỗi: {esc(e)}</p>"

def approve_author_to_trust(author_name, notes):
    if not author_name:
        return "⚠️ Chưa chọn danh tính để phê duyệt.", get_trust_list()
    chain_path = author_paths(author_name)["chain"]
    if not os.path.exists(chain_path):
        return f"❌ Không tìm thấy chứng chỉ của '{esc(author_name)}'.", get_trust_list()
    ok, message = add_to_trust_list(chain_path, added_by="Quản trị viên (UI)", notes=notes or "")
    return message, get_trust_list()

def revoke_trust_entry(entry_id):
    if entry_id is None:
        return "⚠️ Vui lòng nhập ID cần thu hồi.", get_trust_list()
    ok, message = revoke_from_trust_list(int(entry_id))
    return message, get_trust_list()

def refresh_identities():
    update = gr.update(choices=get_author_names())
    return update, update, update

custom_css = """
footer {
    display: none !important;
}
"""

AUTHORS_AT_START = get_author_names()
DEFAULT_AUTHOR = AUTHORS_AT_START[0] if AUTHORS_AT_START else None
DEFAULT_EDITOR = AUTHORS_AT_START[1] if len(AUTHORS_AT_START) > 1 else DEFAULT_AUTHOR

with gr.Blocks(title="C2PA & Watermark Security Suite", css=custom_css) as demo:
    gr.Markdown("# 🛡️ Hệ Thống Bảo Vệ Bản Quyền Ảnh 2 Lớp & Theo Dõi Chỉnh Sửa")
    with gr.Tabs():
        with gr.TabItem("1. Nhúng Watermark & Ký C2PA Gốc"):
            with gr.Row():
                with gr.Column():
                    img_input = gr.Image(type="filepath", label="Ảnh nguyên bản")
                    author_input = gr.Dropdown(choices=AUTHORS_AT_START, value=DEFAULT_AUTHOR,
                                               label="Danh tính người ký (mỗi người một chứng chỉ riêng)")
                    btn_refresh_id_1 = gr.Button("🔄 Tải lại danh sách danh tính", size="sm")
                    btn_sign = gr.Button("🔒 Bảo vệ Ảnh", variant="primary")
                with gr.Column():
                    signed_img_output = gr.Image(label="Ảnh đã ký C2PA & Nhúng Watermark")
                    sign_status = gr.Markdown()
        with gr.TabItem("2. Mô Phỏng Tấn Công"):
            gr.Markdown("### ✂️ Kịch bản A: Xóa metadata (mất manifest, còn watermark)")
            with gr.Row():
                with gr.Column():
                    strip_input = gr.Image(type="filepath", label="Ảnh đã ký C2PA")
                    btn_strip = gr.Button("✂️ Xóa Metadata C2PA", variant="stop")
                with gr.Column():
                    stripped_img_output = gr.Image(label="Ảnh đã bị xóa Metadata")
                    strip_status = gr.Markdown()
            gr.Markdown("### 🖌️ Kịch bản B: Sửa pixel nhưng giữ nguyên manifest (phải bị phát hiện)")
            with gr.Row():
                with gr.Column():
                    tamper_input = gr.File(type="filepath", label="File PNG đã ký C2PA", file_types=[".png"])
                    btn_tamper = gr.Button("🖌️ Sửa Pixel, Giữ Manifest", variant="stop")
                with gr.Column():
                    tampered_output = gr.File(label="File đã bị sửa (tải về rồi đem sang tab 4)")
                    tamper_status = gr.Markdown()
        with gr.TabItem("3. Chỉnh Sửa & Cập Nhật Manifest"):
            gr.Markdown("Xử lý ảnh khi bị sửa đổi để nối tiếp chuỗi **Chain of Custody**")
            with gr.Row():
                with gr.Column():
                    edit_orig_input = gr.Image(type="filepath", label="1. Ảnh gốc (Đã ký C2PA)")
                    edit_mod_input = gr.Image(type="filepath", label="2. Ảnh đã qua chỉnh sửa")
                    editor_input = gr.Dropdown(choices=AUTHORS_AT_START, value=DEFAULT_EDITOR,
                                               label="Danh tính người chỉnh sửa (chứng chỉ riêng)")
                    btn_refresh_id_3 = gr.Button("🔄 Tải lại danh sách danh tính", size="sm")
                    edit_type_input = gr.Dropdown(
                        choices=list(EDIT_ACTION_MAP.keys()),
                        value="crop", label="Loại Chỉnh Sửa (ánh xạ sang hành động chuẩn C2PA)"
                    )
                    edit_desc_input = gr.Textbox(label="Mô Tả Chi Tiết", value="Cắt nhỏ bối cảnh")
                    btn_process_edit = gr.Button("🔄 Ký C2PA Cho Ảnh Đã Sửa", variant="primary")
                with gr.Column():
                    edited_signed_output = gr.Image(label="Ảnh đã chỉnh sửa (Signed)")
                    edit_status = gr.Markdown()
        with gr.TabItem("4. Xác Minh Bản Quyền"):
            with gr.Row():
                with gr.Column():
                    verify_input = gr.Image(type="filepath", label="Ảnh cần xác minh")
                    btn_verify = gr.Button("🔍 Xác Minh (Toàn vẹn + Trust List + Watermark)", variant="primary")
                with gr.Column():
                    verify_report = gr.Markdown()
        with gr.TabItem("5. Chuỗi Chỉnh Sửa & Manifest"):
            gr.Markdown("Xem toàn bộ chuỗi provenance (ingredient chain)")
            with gr.Row():
                with gr.Column():
                    chain_input_img = gr.Image(type="filepath", label="Tải ảnh")
                    btn_trace = gr.Button("🔗 Xem Chuỗi Chỉnh Sửa", variant="primary")
                with gr.Column():
                    chain_report = gr.HTML(label="Chuỗi chỉnh sửa")
        with gr.TabItem("6. Lịch Sử Hệ Thống"):
            history_table = gr.HTML(value=get_history())
            btn_refresh_hist = gr.Button("🔄 Làm Mới Lịch Sử")
        with gr.TabItem("7. Xem Metadata"):
            with gr.Row():
                with gr.Column():
                    metadata_input = gr.Image(type="filepath", label="Tải ảnh")
                    btn_metadata = gr.Button("📋 Kiểm Tra Metadata", variant="primary")
                with gr.Column():
                    metadata_report = gr.HTML(label="Metadata")
        with gr.TabItem("8. Quản Lý Trust List"):
            gr.Markdown("""
            # 🔐 Trust List - Danh Sách CHỨNG CHỈ Được Tin Cậy
            Chỉ ảnh ký bằng chứng chỉ **đã được quản trị viên phê duyệt** mới ở mức **TIN CẬY**.
            Việc ký ảnh **không** tự thêm người ký vào danh sách này.
            Chứng chỉ phải do Root CA của hệ thống cấp thì mới được phê duyệt.
            """)
            with gr.Row():
                with gr.Column():
                    gr.Markdown("### ➕ Phê duyệt chứng chỉ của một tác giả")
                    trust_author_input = gr.Dropdown(choices=AUTHORS_AT_START, value=DEFAULT_AUTHOR,
                                                     label="Danh tính (đã được cấp chứng chỉ)")
                    btn_refresh_id_8 = gr.Button("🔄 Tải lại danh sách danh tính", size="sm")
                    trust_notes_input = gr.Textbox(label="Ghi Chú", value="Đã xác minh danh tính ngoài hệ thống")
                    btn_add_trust = gr.Button("✅ Phê duyệt vào Trust List", variant="primary")
                    trust_status = gr.Markdown()
                with gr.Column():
                    gr.Markdown("### ⛔ Thu hồi chứng chỉ (giữ lại dấu vết)")
                    revoke_id_input = gr.Number(label="ID trong Trust List", precision=0)
                    btn_remove_trust = gr.Button("⛔ Thu hồi", variant="stop")
                    remove_status = gr.Markdown()
            gr.Markdown("### 📋 Danh Sách Chứng Chỉ")
            trust_list_table = gr.HTML(value=get_trust_list())
            btn_refresh_trust = gr.Button("🔄 Làm Mới Danh Sách", size="sm")
        with gr.TabItem("9. Audit Log - Lịch Sử Xác Minh"):
            gr.Markdown("""
            # 📊 Lịch Sử Xác Minh (Verification Audit Log)
            Ghi lại mọi lần xác minh cùng kết quả 4 mức: tin cậy / người ký chưa công nhận / nghi vấn bị sửa / không có credentials.
            """)
            audit_log_table = gr.HTML(value=get_verification_audit_log())
            btn_refresh_audit = gr.Button("🔄 Làm Mới Audit Log")
    identity_dropdowns = [author_input, editor_input, trust_author_input]
    for _btn in (btn_refresh_id_1, btn_refresh_id_3, btn_refresh_id_8):
        _btn.click(fn=refresh_identities, inputs=[], outputs=identity_dropdowns)
    btn_sign.click(fn=process_and_sign, inputs=[img_input, author_input],
                   outputs=[signed_img_output, sign_status, history_table])
    btn_strip.click(fn=strip_metadata_simulation, inputs=[strip_input],
                    outputs=[stripped_img_output, strip_status, history_table])
    btn_tamper.click(fn=tamper_pixels_keep_manifest, inputs=[tamper_input],
                     outputs=[tampered_output, tamper_status, history_table])
    btn_process_edit.click(fn=process_edited_image_with_c2pa,
                           inputs=[edit_orig_input, edit_mod_input, editor_input, edit_type_input, edit_desc_input],
                           outputs=[edited_signed_output, edit_status, history_table])
    btn_verify.click(fn=verify_image, inputs=[verify_input], outputs=[verify_report, history_table])
    btn_trace.click(fn=trace_edit_chain, inputs=[chain_input_img], outputs=[chain_report])
    btn_refresh_hist.click(fn=get_history, inputs=[], outputs=[history_table])
    btn_metadata.click(fn=get_image_metadata, inputs=[metadata_input], outputs=[metadata_report])
    btn_add_trust.click(fn=approve_author_to_trust, inputs=[trust_author_input, trust_notes_input],
                        outputs=[trust_status, trust_list_table])
    btn_remove_trust.click(fn=revoke_trust_entry, inputs=[revoke_id_input],
                           outputs=[remove_status, trust_list_table])
    btn_refresh_trust.click(fn=get_trust_list, inputs=[], outputs=[trust_list_table])
    btn_refresh_audit.click(fn=get_verification_audit_log, inputs=[], outputs=[audit_log_table])

if __name__ == "__main__":
    demo.launch()