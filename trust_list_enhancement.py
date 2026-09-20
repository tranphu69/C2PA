import os
import time
import sqlite3
from datetime import datetime
from html import escape
from cert_manager import get_cert_info, verify_issued_by_root

BASE_DIR = "c2pa_watermark_app"
DB_PATH = os.path.join(BASE_DIR, "history.db")
VERDICT_LABELS = {
    "TRUSTED": ("✅ Tin cậy", "#00b894"),
    "UNKNOWN_SIGNER": ("⚠️ Hợp lệ, người ký chưa được công nhận", "#e67e22"),
    "TAMPERED": ("❌ Nghi vấn / bị thay đổi", "#d63031"),
    "NO_CREDENTIALS": ("➖ Không có Content Credentials", "#636e72"),
    "ERROR": ("❓ Không thể kết luận", "#6c5ce7"),
}

def _connect():
    os.makedirs(BASE_DIR, exist_ok=True)
    return sqlite3.connect(DB_PATH)

def _columns(cursor, table):
    return [r[1] for r in cursor.execute(f"PRAGMA table_info({table})")]

def _ensure_column(cursor, table, column, decl):
    if column not in _columns(cursor, table):
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")

def init_trust_list_db():
    conn = _connect()
    cursor = conn.cursor()
    old_cols = _columns(cursor, "trust_list")
    if old_cols and "cert_serial" not in old_cols:
        cursor.execute(f"ALTER TABLE trust_list RENAME TO trust_list_legacy_{int(time.time())}")
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trust_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cert_serial TEXT UNIQUE NOT NULL,   -- serial (thập phân) của chứng chỉ leaf
            cert_hash TEXT UNIQUE NOT NULL,     -- SHA-256 của chứng chỉ leaf (DER)
            author_name TEXT NOT NULL,          -- CN trong chứng chỉ
            organization TEXT,                  -- O trong chứng chỉ
            cert_subject TEXT,
            cert_not_after TEXT,
            added_timestamp TEXT,
            added_by TEXT,
            is_approved BOOLEAN DEFAULT 1,
            revoked_timestamp TEXT,
            notes TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS verification_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            verified_image TEXT,
            cert_hash TEXT,
            author_name TEXT,
            is_trusted BOOLEAN,
            verification_timestamp TEXT,
            verification_detail TEXT
        )
    """)
    _ensure_column(cursor, "verification_audit", "cert_serial", "TEXT")
    _ensure_column(cursor, "verification_audit", "verdict", "TEXT")
    conn.commit()
    conn.close()
    print("✅ Trust List database initialized")

def add_to_trust_list(cert_pem_path, added_by="Admin", notes=""):
    try:
        with open(cert_pem_path, "rb") as f:
            pem = f.read()
        ok, why = verify_issued_by_root(pem)
        if not ok:
            return False, f"Từ chối: {why}"
        info = get_cert_info(pem)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute("SELECT id, is_approved FROM trust_list WHERE cert_serial = ?", (info["serial"],))
        row = cursor.fetchone()
        if row:
            if row[1]:
                conn.close()
                return False, f"⚠️ Chứng chỉ của '{info['cn']}' đã có trong Trust List (ID {row[0]})"
            cursor.execute(
                "UPDATE trust_list SET is_approved = 1, revoked_timestamp = NULL, added_by = ?, notes = ? WHERE id = ?",
                (added_by, notes, row[0]),
            )
            conn.commit()
            conn.close()
            return True, f"✅ Đã khôi phục chứng chỉ của '{info['cn']}' (ID {row[0]})"
        cursor.execute("""
            INSERT INTO trust_list
            (cert_serial, cert_hash, author_name, organization, cert_subject, cert_not_after,
             added_timestamp, added_by, is_approved, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (info["serial"], info["sha256"], info["cn"], info["org"], info["subject"],
              info["not_after"], now, added_by, notes))
        conn.commit()
        conn.close()
        return True, f"✅ Đã phê duyệt '{info['cn']}' ({info['org']}) - SHA-256: {info['sha256'][:16]}..."
    except Exception as e:
        return False, f"❌ Lỗi: {e}"

def revoke_from_trust_list(entry_id):
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute("SELECT author_name, is_approved FROM trust_list WHERE id = ?", (int(entry_id),))
        row = cursor.fetchone()
        if not row:
            conn.close()
            return False, f"⚠️ Không có mục ID {entry_id} trong Trust List"
        if not row[1]:
            conn.close()
            return False, f"⚠️ Mục ID {entry_id} ('{row[0]}') đã bị thu hồi từ trước"
        cursor.execute(
            "UPDATE trust_list SET is_approved = 0, revoked_timestamp = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), int(entry_id)),
        )
        conn.commit()
        conn.close()
        return True, f"✅ Đã thu hồi chứng chỉ của '{row[0]}' (ID {entry_id}). Các ảnh đã ký bằng nó sẽ không còn được coi là tin cậy."
    except Exception as e:
        return False, f"❌ Lỗi: {e}"

def _serial_candidates(serial):
    s = str(serial).strip().replace(":", "").replace(" ", "")
    out = set()
    for base in (10, 16):
        try:
            out.add(int(s, base))
        except ValueError:
            pass
    return out

def find_trust_entry(serial):
    if not serial:
        return None
    candidates = _serial_candidates(serial)
    if not candidates:
        return None
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, cert_serial, cert_hash, author_name, organization, is_approved, revoked_timestamp
        FROM trust_list
    """)
    rows = cursor.fetchall()
    conn.close()
    for r in rows:
        try:
            if int(r[1]) in candidates:
                return {
                    "id": r[0], "serial": r[1], "cert_hash": r[2], "author_name": r[3],
                    "organization": r[4], "is_approved": bool(r[5]), "revoked_timestamp": r[6],
                }
        except ValueError:
            continue
    return None

def check_if_trusted(cert_pem_bytes):
    info = get_cert_info(cert_pem_bytes)
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT author_name, organization FROM trust_list WHERE cert_hash = ? AND is_approved = 1",
        (info["sha256"],),
    )
    row = cursor.fetchone()
    conn.close()
    if row:
        return True, {"author_name": row[0], "organization": row[1], "sha256": info["sha256"]}
    return False, None

def get_trust_list():
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, author_name, organization, cert_serial, cert_hash, cert_not_after,
               added_timestamp, added_by, is_approved, revoked_timestamp, notes
        FROM trust_list ORDER BY id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    if not rows:
        return "<p style='color: #888;'>Trust List đang trống. Hãy phê duyệt ít nhất một tác giả.</p>"

    html = """
    <table style="width:100%; border-collapse: collapse; text-align: left; font-size: 12px;">
    <tr style="background-color: #2d3436; color: white; border-bottom: 2px solid #00b894;">
        <th style="padding: 10px;">ID</th><th style="padding: 10px;">Tác giả (CN)</th>
        <th style="padding: 10px;">Tổ chức</th><th style="padding: 10px;">Serial</th>
        <th style="padding: 10px;">SHA-256</th><th style="padding: 10px;">Hết hạn</th>
        <th style="padding: 10px;">Phê duyệt</th><th style="padding: 10px;">Trạng thái</th>
        <th style="padding: 10px;">Ghi chú</th>
    </tr>
    """
    for r in rows:
        approved = bool(r[8])
        color = "#00b894" if approved else "#d63031"
        text = "✅ Tin cậy" if approved else f"⛔ Đã thu hồi ({escape(str(r[9]))})"
        html += f"""
        <tr style="border-bottom: 1px solid #dfe6e9;">
            <td style="padding: 8px;"><b>{r[0]}</b></td>
            <td style="padding: 8px;"><b style="color: #0984e3;">{escape(str(r[1]))}</b></td>
            <td style="padding: 8px;">{escape(str(r[2] or '-'))}</td>
            <td style="padding: 8px; font-family: monospace;">{escape(str(r[3])[:14])}...</td>
            <td style="padding: 8px; font-family: monospace;">{escape(str(r[4])[:16])}...</td>
            <td style="padding: 8px;">{escape(str(r[5] or '-'))}</td>
            <td style="padding: 8px;">{escape(str(r[6]))}<br><i>{escape(str(r[7] or ''))}</i></td>
            <td style="padding: 8px; color: {color}; font-weight: bold;">{text}</td>
            <td style="padding: 8px;">{escape(str(r[10] or '-'))}</td>
        </tr>
        """
    return html + "</table>"

def log_verification_audit(image_filename, cert_serial, author_name, verdict, detail):
    try:
        conn = _connect()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO verification_audit
            (verified_image, cert_serial, author_name, is_trusted, verdict, verification_timestamp, verification_detail)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (image_filename, cert_serial, author_name, 1 if verdict == "TRUSTED" else 0, verdict,
              datetime.now().strftime("%Y-%m-%d %H:%M:%S"), detail))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ Lỗi ghi log: {e}")

def get_verification_audit_log():
    conn = _connect()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, verified_image, author_name, is_trusted, verdict, cert_serial,
               verification_timestamp, verification_detail
        FROM verification_audit ORDER BY id DESC LIMIT 50
    """)
    rows = cursor.fetchall()
    conn.close()

    if not rows:
        return "<p style='color: #888;'>Chưa có lịch sử xác minh nào.</p>"

    html = """
    <table style="width:100%; border-collapse: collapse; text-align: left; font-size: 12px;">
    <tr style="background-color: #2d3436; color: white; border-bottom: 2px solid #6c5ce7;">
        <th style="padding: 10px;">ID</th><th style="padding: 10px;">Ảnh</th>
        <th style="padding: 10px;">Người ký</th><th style="padding: 10px;">Kết quả</th>
        <th style="padding: 10px;">Serial</th><th style="padding: 10px;">Thời gian</th>
        <th style="padding: 10px;">Chi tiết</th>
    </tr>
    """
    for r in rows:
        verdict = r[4] or ("TRUSTED" if r[3] else "UNKNOWN_SIGNER")
        label, color = VERDICT_LABELS.get(verdict, (verdict, "#636e72"))
        serial = (str(r[5])[:12] + "...") if r[5] and r[5] != "unknown" else "-"
        html += f"""
        <tr style="border-bottom: 1px solid #dfe6e9;">
            <td style="padding: 8px;"><b>{r[0]}</b></td>
            <td style="padding: 8px;">{escape(str(r[1]))}</td>
            <td style="padding: 8px;"><b>{escape(str(r[2]))}</b></td>
            <td style="padding: 8px; color: {color}; font-weight: bold;">{label}</td>
            <td style="padding: 8px; font-family: monospace;">{escape(serial)}</td>
            <td style="padding: 8px;">{escape(str(r[6]))}</td>
            <td style="padding: 8px; font-size: 11px;">{escape(str(r[7] or ''))}</td>
        </tr>
        """
    return html + "</table>"

if __name__ == "__main__":
    init_trust_list_db()
    print("Trust List module initialized successfully!")