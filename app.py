from __future__ import annotations

import os
import functools
import time
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from dateutil import parser
from flask import Flask, Response, flash, jsonify, redirect, render_template, request, session, url_for
from postgrest.exceptions import APIError

from config import load_config
from database import get_db

cfg = load_config()
db = get_db()

app = Flask(__name__)
app.secret_key = cfg.get("FLASK_SECRET_KEY") or "dev_only_change_me"

# --- API rate limit (per-process, in-memory) ---
_rate_state: dict[str, tuple[float, float]] = {}  # ip -> (tokens, last_ts)


def _utc_now() -> datetime:
    return datetime.utcnow()


def _iso_now() -> str:
    return _utc_now().isoformat()


def get_request_ip() -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit(ip: str) -> bool:
    burst = int(cfg.get("API_RATE_LIMIT_BURST") or 30)
    per_min = float(cfg.get("API_RATE_LIMIT_PER_MINUTE") or 120)
    refill_per_sec = per_min / 60.0

    now = time.time()
    tokens, last = _rate_state.get(ip, (float(burst), now))
    tokens = min(float(burst), tokens + (now - last) * refill_per_sec)

    if tokens < 1.0:
        _rate_state[ip] = (tokens, now)
        return False

    _rate_state[ip] = (tokens - 1.0, now)
    return True


def parse_json() -> dict:
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def log_security_event(key: str | None, ip: str | None, hwid: str | None, msg: str, severity: str = "info") -> None:
    """
    Zapisuje zdarzenie w tabeli access_logs (best-effort).
    """
    try:
        db.table("access_logs").insert(
            {
                "license_key": key,
                "ip_address": ip,
                "hwid_attempt": hwid,
                "message": msg,
                "severity": severity,
            }
        ).execute()
    except Exception:
        # nie blokuj API/panelu na awarii logowania
        pass


def _is_expired(lic: dict) -> bool:
    expires_at = lic.get("expires_at")
    if not expires_at:
        return False
    try:
        expire_dt = parser.isoparse(expires_at).replace(tzinfo=None)
    except Exception:
        return False
    return expire_dt < _utc_now()


def _fetch_license(key: str) -> dict | None:
    res = db.table("licenses").select("*").eq("license_key", key).limit(1).execute()
    return res.data[0] if res.data else None


def _touch_license_heartbeat(key: str, ip: str, ua: str | None, app_version: str | None) -> None:
    """
    Spróbuje zaktualizować heartbeat na rekordzie licencji (jeśli kolumny istnieją).
    """
    try:
        db.table("licenses").update(
            {
                "last_seen": _iso_now(),
                "last_ip": ip,
                "last_user_agent": ua,
                "last_app_version": app_version,
            }
        ).eq("license_key", key).execute()
    except Exception:
        pass


def _ensure_device_binding(key: str, lic: dict, hwid: str, ip: str, ua: str | None, app_version: str | None) -> tuple[bool, str, dict | None]:
    """
    Preferowany tryb: tabela license_devices (wielourządzeniowość).
    Fallback: legacy licenses.hwid (1 urządzenie).

    Returns: (ok, message, device_row_or_none)
    """
    max_devices = int(lic.get("max_devices") or 1)

    # --- Nowy model (license_devices) ---
    try:
        existing = (
            db.table("license_devices")
            .select("*")
            .eq("license_key", key)
            .eq("hwid", hwid)
            .limit(1)
            .execute()
        ).data

        if existing:
            device = existing[0]
            if device.get("status") == "banned":
                return False, "Device Banned", device

            # update last_seen
            try:
                db.table("license_devices").update(
                    {
                        "last_seen": _iso_now(),
                        "last_ip": ip,
                        "user_agent": ua,
                        "app_version": app_version,
                    }
                ).eq("id", device["id"]).execute()
            except Exception:
                pass

            return True, "OK", device

        # nie ma urządzenia -> policz aktywne
        active_devices = (
            db.table("license_devices")
            .select("id, status")
            .eq("license_key", key)
            .eq("status", "active")
            .limit(max_devices + 1)
            .execute()
        ).data or []

        if len(active_devices) >= max_devices:
            return False, "Device Limit Reached", None

        device = (
            db.table("license_devices")
            .insert(
                {
                    "license_key": key,
                    "hwid": hwid,
                    "status": "active",
                    "first_seen": _iso_now(),
                    "last_seen": _iso_now(),
                    "last_ip": ip,
                    "user_agent": ua,
                    "app_version": app_version,
                }
            )
            .execute()
            .data
        )
        device_row = device[0] if device else None
        return True, "OK", device_row

    except APIError:
        # tabela nie istnieje / brak uprawnień -> fallback legacy
        pass
    except Exception:
        # cokolwiek innego -> fallback legacy (nie blokuj)
        pass

    # --- Legacy (licenses.hwid) ---
    current_hwid = lic.get("hwid")
    if current_hwid is None:
        try:
            db.table("licenses").update({"hwid": hwid}).eq("license_key", key).execute()
        except Exception:
            pass
        return True, "OK", None

    if current_hwid != hwid:
        return False, "HWID Mismatch", None

    return True, "OK", None


def _create_session(key: str, device_id: int | None, ip: str, ua: str | None, app_version: str | None) -> str | None:
    """
    Tworzy sesję (opcjonalnie) — jeśli tabela license_sessions istnieje.
    """
    try:
        sid = str(uuid.uuid4())
        db.table("license_sessions").insert(
            {
                "id": sid,
                "license_key": key,
                "device_id": device_id,
                "status": "active",
                "started_at": _iso_now(),
                "last_seen": _iso_now(),
                "last_ip": ip,
                "user_agent": ua,
                "app_version": app_version,
            }
        ).execute()
        return sid
    except APIError:
        return None
    except Exception:
        return None


def _touch_session(session_id: str, ip: str, ua: str | None, app_version: str | None) -> None:
    try:
        db.table("license_sessions").update(
            {"last_seen": _iso_now(), "last_ip": ip, "user_agent": ua, "app_version": app_version}
        ).eq("id", session_id).execute()
    except Exception:
        pass


# --- ROUTY AUTORYZACJI (ADMIN) ---
@app.route("/login", methods=["GET", "POST"])
def login():
    admin_password = cfg.get("ADMIN_PASSWORD")
    if request.method == "POST":
        if not admin_password:
            flash("Brak ADMIN_PASSWORD w konfiguracji serwera.", "error")
        elif request.form.get("password") == admin_password:
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            flash("Błędne hasło.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- DASHBOARD I ZARZĄDZANIE ---
@app.route("/")
@login_required
def index():
    try:
        licenses = db.table("licenses").select("*").order("created_at", desc=True).execute().data or []
    except APIError as e:
        if "PGRST205" in str(e) or "Could not find the table" in str(e):
            flash("Błąd: Tabela 'licenses' nie istnieje w bazie danych. Uruchom plik supabase_schema.sql w Supabase SQL Editor.", "error")
            licenses = []
        else:
            raise
    
    now = _utc_now()
    for lic in licenses:
        lic["is_expired"] = False
        if lic.get("expires_at"):
            try:
                expire_dt = parser.isoparse(lic["expires_at"]).replace(tzinfo=None)
                lic["is_expired"] = expire_dt < now
            except Exception:
                lic["is_expired"] = False

    try:
        logs = db.table("access_logs").select("*").order("created_at", desc=True).limit(50).execute().data or []
    except APIError as e:
        if "PGRST205" in str(e) or "Could not find the table" in str(e):
            logs = []
        else:
            raise
    
    return render_template("dashboard.html", licenses=licenses, logs=logs, admin_id=cfg.get("ADMIN_ID"))


@app.route("/export_keys")
@login_required
def export_keys():
    try:
        data = db.table("licenses").select("license_key, note, telegram_username").order("created_at", desc=True).execute().data or []
    except APIError:
        data = []
    lines = []
    for row in data:
        key = row.get("license_key") or ""
        note = (row.get("note") or "").strip()
        tg = (row.get("telegram_username") or "").strip()
        line = key
        if note or tg:
            line += "\t" + note + (" @" + tg if tg else "")
        lines.append(line.strip())
    body = "\n".join(lines) or "(brak licencji)"
    return Response(body, mimetype="text/plain; charset=utf-8", headers={
        "Content-Disposition": "attachment; filename=thundert_klucze.txt",
    })


def _safe_table_data(table: str, select: str = "*", order: str | None = "created_at", limit: int | None = None) -> list:
    try:
        q = db.table(table).select(select)
        if order:
            q = q.order(order, desc=True)
        if limit:
            q = q.limit(limit)
        return (q.execute().data or [])
    except APIError:
        return []


@app.route("/api/live_stats")
@login_required
def api_live_stats():
    """
    Zwraca statystyki na żywo dla widgetu dashboardu.
    """
    now = _utc_now()
    one_hour_ago = (now - timedelta(hours=1)).isoformat()
    
    try:
        # Online users (last_seen within last hour)
        online_licenses = db.table("licenses").select("id").gte("last_seen", one_hour_ago).execute().data or []
        online_devices = db.table("license_devices").select("id").gte("last_seen", one_hour_ago).eq("status", "active").execute().data or []
        online_sessions = db.table("license_sessions").select("id").gte("last_seen", one_hour_ago).eq("status", "active").execute().data or []
        
        # Unique online users (combine licenses, devices, sessions)
        online_users = len(set([l.get("id") for l in online_licenses] + 
                               [d.get("id") for d in online_devices] + 
                               [s.get("id") for s in online_sessions]))
        
        # Active sessions
        active_sessions = len(online_sessions)
        
        # Active licenses
        active_licenses = db.table("licenses").select("id").eq("status", "active").execute().data or []
        active_licenses_count = len(active_licenses)
        
        # Verifications in last hour (from access_logs)
        verifications = db.table("access_logs").select("id").gte("created_at", one_hour_ago).execute().data or []
        verifications_1h = len(verifications)
        
        # Hourly activity for chart (last 12 hours)
        hourly_activity = []
        for i in range(12):
            hour_start = now - timedelta(hours=i+1)
            hour_end = now - timedelta(hours=i)
            hour_start_iso = hour_start.isoformat()
            hour_end_iso = hour_end.isoformat()
            
            try:
                hour_logs = db.table("access_logs").select("id").gte("created_at", hour_start_iso).lt("created_at", hour_end_iso).execute().data or []
                count = len(hour_logs)
            except Exception:
                count = 0
            
            hour_label = hour_start.strftime("%H:00")
            hourly_activity.append({"hour": hour_label, "count": count})
        
        hourly_activity.reverse()  # Oldest to newest
        
        return jsonify({
            "online_users": online_users,
            "active_sessions": active_sessions,
            "verifications_1h": verifications_1h,
            "active_licenses": active_licenses_count,
            "hourly_activity": hourly_activity
        })
    except Exception as e:
        return jsonify({
            "online_users": 0,
            "active_sessions": 0,
            "verifications_1h": 0,
            "active_licenses": 0,
            "hourly_activity": []
        }), 500


@app.route("/stats")
@login_required
def stats():
    now = _utc_now()
    licenses = _safe_table_data("licenses", limit=10_000)
    devices = _safe_table_data("license_devices", select="id, license_key, status", limit=50_000)
    sessions = _safe_table_data("license_sessions", select="id, license_key, status", limit=20_000)
    logs = _safe_table_data("access_logs", limit=5_000)

    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}
    created_7d = created_30d = 0
    for lic in licenses:
        t = (lic.get("license_type") or "BASIC").upper()
        by_type[t] = by_type.get(t, 0) + 1
        s = (lic.get("status") or "active").lower()
        by_status[s] = by_status.get(s, 0) + 1
        try:
            ct = parser.isoparse(lic.get("created_at") or "").replace(tzinfo=None)
            if (now - ct).days <= 7:
                created_7d += 1
            if (now - ct).days <= 30:
                created_30d += 1
        except Exception:
            pass

    active_sessions = sum(1 for s in sessions if (s.get("status") or "").lower() == "active")
    by_severity: dict[str, int] = {}
    for log in logs:
        sev = (log.get("severity") or "info").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1

    created_per_day: dict[str, int] = defaultdict(int)
    for lic in licenses:
        try:
            ct = (lic.get("created_at") or "")[:10]
            if ct:
                created_per_day[ct] += 1
        except Exception:
            pass
    created_per_day = dict(sorted(created_per_day.items(), reverse=True)[:14])

    stats_data = {
        "total_licenses": len(licenses),
        "by_type": by_type,
        "by_status": by_status,
        "created_7d": created_7d,
        "created_30d": created_30d,
        "total_devices": len(devices),
        "active_sessions": active_sessions,
        "by_severity": by_severity,
        "created_per_day": created_per_day,
        "total_logs_sampled": len(logs),
    }
    return render_template("stats.html", stats=stats_data, admin_id=cfg.get("ADMIN_ID"))


@app.route("/license/<int:license_id>")
@login_required
def license_detail(license_id: int):
    res = db.table("licenses").select("*").eq("id", license_id).limit(1).execute()
    lic = res.data[0] if res.data else None
    if not lic:
        flash("Nie znaleziono licencji.", "error")
        return redirect(url_for("index"))

    now = _utc_now()
    lic["is_expired"] = False
    if lic.get("expires_at"):
        try:
            expire_dt = parser.isoparse(lic["expires_at"]).replace(tzinfo=None)
            lic["is_expired"] = expire_dt < now
        except Exception:
            pass

    key = lic.get("license_key")
    devices = _safe_table_data("license_devices", limit=500)
    devices = [d for d in devices if d.get("license_key") == key]
    sessions = _safe_table_data("license_sessions", limit=500)
    sessions = [s for s in sessions if s.get("license_key") == key]
    all_logs = _safe_table_data("access_logs", limit=1000)
    logs = [l for l in all_logs if l.get("license_key") == key][:50]

    return render_template(
        "license_detail.html",
        lic=lic,
        devices=devices,
        sessions=sessions,
        logs=logs,
        admin_id=cfg.get("ADMIN_ID"),
    )


@app.route("/license/<int:license_id>/update", methods=["POST"])
@login_required
def license_update(license_id: int):
    note = request.form.get("note", "").strip()
    telegram = (request.form.get("telegram_username") or "").strip().lstrip("@") or None
    license_type = (request.form.get("license_type") or "PRO").strip().upper()
    status = (request.form.get("status") or "active").strip().lower()
    max_phones = request.form.get("max_phones")
    expires_at = request.form.get("expires_at", "").strip()
    extend_days = request.form.get("extend_days", "").strip()

    update: dict = {"note": note, "license_type": license_type, "status": status, "telegram_username": telegram}

    if max_phones is not None and max_phones != "":
        try:
            update["max_phones"] = max(1, int(max_phones))
        except ValueError:
            pass

    if extend_days and int(extend_days) > 0:
        try:
            res = db.table("licenses").select("expires_at").eq("id", license_id).limit(1).execute()
            cur = (res.data[0] if res.data else {}).get("expires_at")
            if cur:
                base = parser.isoparse(cur).replace(tzinfo=None)
                if base < _utc_now():
                    base = _utc_now()
            else:
                base = _utc_now()
            new_date = base + timedelta(days=int(extend_days))
            update["expires_at"] = new_date.isoformat()
            if status != "banned":
                update["status"] = "active"
        except Exception:
            pass
    elif expires_at:
        try:
            dt = parser.parse(expires_at)
            if dt.tzinfo:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            else:
                dt = dt.replace(tzinfo=None)
            update["expires_at"] = dt.isoformat()
        except Exception:
            pass

    try:
        db.table("licenses").update(update).eq("id", license_id).execute()
        flash("Zaktualizowano licencję.", "success")
    except Exception as e:
        flash(f"Błąd: {e}", "error")
    return redirect(url_for("license_detail", license_id=license_id))


@app.route("/create", methods=["POST"])
@login_required
def create_license():
    note = request.form.get("note", "").strip()
    telegram = (request.form.get("telegram_username") or "").strip().lstrip("@") or None
    l_type = request.form.get("license_type", "BASIC")
    duration = request.form.get("duration", "30")
    max_phones_raw = request.form.get("max_phones", "1").strip()

    expires_at = None
    if duration != "lifetime":
        days = int(duration)
        expires_at = (_utc_now() + timedelta(days=days)).isoformat()

    max_phones = 1
    if max_phones_raw:
        try:
            max_phones = max(1, int(max_phones_raw))
        except ValueError:
            pass

    new_key = str(uuid.uuid4()).upper()
    insert_data = {
        "license_key": new_key,
        "note": note,
        "telegram_username": telegram,
        "status": "active",
        "license_type": l_type,
        "expires_at": expires_at,
        "max_phones": max_phones,
    }
    try:
        db.table("licenses").insert(insert_data).execute()
    except Exception:
        for k in ("max_phones", "telegram_username"):
            insert_data.pop(k, None)
        db.table("licenses").insert(insert_data).execute()

    flash(f"Utworzono: {l_type} ({duration})", "success")
    return redirect(url_for("index"))


@app.route("/edit_license", methods=["POST"])
@login_required
def edit_license():
    lic_id_raw = request.form.get("id")
    new_note = request.form.get("note")
    extend_days = request.form.get("extend_days")

    update_data = {"note": new_note}

    if extend_days and int(extend_days) > 0 and lic_id_raw:
        try:
            lic_id = int(lic_id_raw)
        except Exception:
            lic_id = lic_id_raw

        res = db.table("licenses").select("expires_at").eq("id", lic_id).limit(1).execute()
        current_expires = (res.data[0] if res.data else {}).get("expires_at")

        if current_expires:
            base_date = parser.isoparse(current_expires)
            if base_date.replace(tzinfo=None) < _utc_now():
                base_date = _utc_now()
            new_date = base_date + timedelta(days=int(extend_days))
            update_data["expires_at"] = new_date.isoformat()
            update_data["status"] = "active"
        else:
            # licencja lifetime -> ustaw datę od teraz
            new_date = _utc_now() + timedelta(days=int(extend_days))
            update_data["expires_at"] = new_date.isoformat()
            update_data["status"] = "active"

    if lic_id_raw:
        try:
            lic_id = int(lic_id_raw)
        except Exception:
            lic_id = lic_id_raw
        db.table("licenses").update(update_data).eq("id", lic_id).execute()
        flash("Zaktualizowano licencję.", "success")
    else:
        flash("Brak ID licencji.", "error")

    return redirect(url_for("index"))


def _safe_redirect_target() -> str | None:
    r = request.form.get("redirect") or request.args.get("redirect") or ""
    r = (r or "").strip()
    if not r or "//" in r or r.startswith("javascript:") or "\n" in r:
        return None
    if r.startswith("/") and len(r) < 500:
        return r
    return None


@app.route("/action/<action_type>/<int:license_id>", methods=["POST"])
@login_required
def license_action(action_type: str, license_id: int):
    redirect_to = _safe_redirect_target()
    if action_type == "delete":
        db.table("licenses").delete().eq("id", license_id).execute()
        flash("Usunięto licencję.", "warning")
        redirect_to = None
    elif action_type == "ban":
        db.table("licenses").update({"status": "banned"}).eq("id", license_id).execute()
        flash("Zbanowano licencję.", "danger")
    elif action_type == "unban":
        db.table("licenses").update({"status": "active"}).eq("id", license_id).execute()
        flash("Odblokowano licencję.", "success")
    elif action_type == "reset_hwid":
        db.table("licenses").update({"hwid": None}).eq("id", license_id).execute()
        flash("Zresetowano HWID (legacy).", "info")
    elif action_type == "reset_devices":
        lic = db.table("licenses").select("license_key").eq("id", license_id).limit(1).execute().data
        lic_key = lic[0]["license_key"] if lic else None
        if lic_key:
            try:
                db.table("license_devices").delete().eq("license_key", lic_key).execute()
            except Exception:
                pass
            try:
                db.table("license_sessions").delete().eq("license_key", lic_key).execute()
            except Exception:
                pass
            try:
                db.table("licenses").update({"hwid": None}).eq("license_key", lic_key).execute()
            except Exception:
                pass
            flash("Zresetowano urządzenia + sesje (heartbeat).", "info")
        else:
            flash("Nie znaleziono licencji.", "error")
    if redirect_to:
        return redirect(redirect_to)
    return redirect(url_for("index"))


# --- API v1 ---
@app.route("/api/v1/health", methods=["GET"])
def api_health():
    return jsonify({"ok": True, "time": _iso_now()}), 200


@app.route("/api/v1/verify", methods=["POST"])
def api_verify_v1():
    ip = get_request_ip()
    ua = request.headers.get("User-Agent")

    if not rate_limit(ip):
        return jsonify({"valid": False, "message": "Rate Limited"}), 429

    data = parse_json()
    key = (data.get("key") or "").strip()
    hwid = (data.get("hwid") or "").strip()
    app_version = (data.get("app_version") or "").strip() or None

    if not key or not hwid:
        return jsonify({"valid": False, "message": "Missing key/hwid"}), 400

    lic = _fetch_license(key)
    if not lic:
        log_security_event(key, ip, hwid, "Invalid key", "warning")
        return jsonify({"valid": False, "message": "Invalid Key"}), 403

    if lic.get("status") == "banned":
        log_security_event(key, ip, hwid, "Banned license", "warning")
        return jsonify({"valid": False, "message": "License Banned"}), 403

    if _is_expired(lic):
        if lic.get("status") != "expired":
            try:
                db.table("licenses").update({"status": "expired"}).eq("license_key", key).execute()
            except Exception:
                pass
        return jsonify({"valid": False, "message": "License Expired"}), 403

    ok, msg, device = _ensure_device_binding(key, lic, hwid, ip, ua, app_version)
    if not ok:
        severity = "critical" if msg in ("HWID Mismatch", "Device Limit Reached") else "warning"
        log_security_event(key, ip, hwid, msg, severity)
        return jsonify({"valid": False, "message": msg}), 403

    _touch_license_heartbeat(key, ip, ua, app_version)

    session_id = _create_session(key, device.get("id") if isinstance(device, dict) else None, ip, ua, app_version)

    return jsonify(
        {
            "valid": True,
            "type": lic.get("license_type"),
            "expires": lic.get("expires_at"),
            "server_time": _iso_now(),
            "heartbeat_timeout_seconds": int(lic.get("heartbeat_timeout_seconds") or 180),
            "offline_grace_seconds": int(lic.get("offline_grace_seconds") or 86400),
            "max_phones": int(lic.get("max_phones") or 1),
            "session_id": session_id,
            "message": "Access Granted",
        }
    ), 200


@app.route("/api/v1/heartbeat", methods=["POST"])
def api_heartbeat_v1():
    ip = get_request_ip()
    ua = request.headers.get("User-Agent")

    if not rate_limit(ip):
        return jsonify({"ok": False, "message": "Rate Limited"}), 429

    data = parse_json()
    key = (data.get("key") or "").strip()
    hwid = (data.get("hwid") or "").strip()
    app_version = (data.get("app_version") or "").strip() or None
    session_id = (data.get("session_id") or "").strip() or None

    if not key or not hwid:
        return jsonify({"ok": False, "message": "Missing key/hwid"}), 400

    lic = _fetch_license(key)
    if not lic:
        log_security_event(key, ip, hwid, "Invalid key (heartbeat)", "warning")
        return jsonify({"ok": False, "message": "Invalid Key"}), 403

    if lic.get("status") == "banned":
        return jsonify({"ok": False, "message": "License Banned"}), 403

    if _is_expired(lic):
        return jsonify({"ok": False, "message": "License Expired"}), 403

    ok, msg, _device = _ensure_device_binding(key, lic, hwid, ip, ua, app_version)
    if not ok:
        log_security_event(key, ip, hwid, f"Heartbeat rejected: {msg}", "warning")
        return jsonify({"ok": False, "message": msg}), 403

    _touch_license_heartbeat(key, ip, ua, app_version)
    if session_id:
        _touch_session(session_id, ip, ua, app_version)

    return jsonify(
        {
            "ok": True,
            "server_time": _iso_now(),
            "heartbeat_timeout_seconds": int(lic.get("heartbeat_timeout_seconds") or 180),
            "max_phones": int(lic.get("max_phones") or 1),
            "message": "Heartbeat OK",
        }
    ), 200


# --- Backwards compatibility ---
@app.route("/api/verify", methods=["POST"])
def verify_license_legacy():
    """
    Zostawione dla kompatybilności ze starym klientem.
    """
    resp, code = api_verify_v1()
    payload = resp.get_json() if hasattr(resp, "get_json") else {}
    if code != 200:
        return jsonify({"valid": False, "message": payload.get("message", "Denied")}), code
    return jsonify({
        "valid": True,
        "type": payload.get("type"),
        "expires": payload.get("expires"),
        "max_phones": payload.get("max_phones", 1),
        "message": "OK",
    }), 200


if __name__ == "__main__":
    port = int((os.getenv("PORT") or "5000").strip())
    debug = (os.getenv("FLASK_DEBUG") or "").strip() == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)