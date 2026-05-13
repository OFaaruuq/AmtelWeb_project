from __future__ import annotations

import csv
import io
import os
import secrets
import time
import traceback
import uuid
from collections import defaultdict, deque
from decimal import Decimal
from functools import wraps
from typing import Any

import click
from dotenv import load_dotenv
from flask import Flask, Response, abort, flash, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from analytics_repository import (
    TARGET_PAGE_LABELS,
    admin_session_active,
    analytics_breakdown,
    conversion_summary,
    dashboard_data,
    distinct_paths,
    fetch_clicks,
    fetch_conversions,
    fetch_engagement,
    fetch_logs,
    fetch_visits,
    init_database,
    log_admin_activity,
    log_error,
    log_request,
    log_suspicious_activity,
    engagement_summary,
    realtime_data,
    refresh_analytics_aggregates,
    report_data,
    revoke_admin_session,
    touch_admin_session,
    top_clicks,
    upsert_admin_session,
    visitor_ip_summary,
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("ADMIN_SECRET_KEY", "change-this-admin-secret-key")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = os.getenv("ADMIN_COOKIE_SAMESITE", "Lax")
app.config["SESSION_COOKIE_SECURE"] = os.getenv("ADMIN_COOKIE_SECURE", "false").lower() in {"1", "true", "yes"}
app.config["PERMANENT_SESSION_LIFETIME"] = int(os.getenv("ADMIN_SESSION_SECONDS", "28800"))

LOGIN_ATTEMPTS: dict[str, deque[float]] = defaultdict(deque)
LOGIN_RATE_LIMIT = int(os.getenv("ADMIN_LOGIN_RATE_LIMIT", "5"))
LOGIN_RATE_WINDOW_SECONDS = int(os.getenv("ADMIN_LOGIN_RATE_WINDOW_SECONDS", "300"))
SESSION_CHECK_INTERVAL_SECONDS = int(os.getenv("ADMIN_SESSION_CHECK_INTERVAL_SECONDS", "60"))


def client_ip_address() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.headers.get("X-Real-IP") or request.remote_addr or "0.0.0.0"


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return str(token)


def validate_csrf() -> None:
    sent_token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token")
    if not sent_token or not secrets.compare_digest(sent_token, str(session.get("csrf_token", ""))):
        safe_log_suspicious_activity(client_ip_address(), "csrf_validation_failed", "high", None)
        abort(400, "Invalid CSRF token.")


def rate_limit_login() -> bool:
    now = time.time()
    key = client_ip_address()
    attempts = LOGIN_ATTEMPTS[key]
    while attempts and attempts[0] < now - LOGIN_RATE_WINDOW_SECONDS:
        attempts.popleft()
    if len(attempts) >= LOGIN_RATE_LIMIT:
        safe_log_suspicious_activity(key, "login_rate_limited", "medium", None)
        return False
    attempts.append(now)
    return True


def clear_login_attempts() -> None:
    LOGIN_ATTEMPTS.pop(client_ip_address(), None)


def safe_log_suspicious_activity(ip_address: str | None, event_type: str, severity: str, details: str | None = None) -> None:
    try:
        init_database()
        log_suspicious_activity(ip_address, event_type, severity, details)
    except Exception as exc:
        app.logger.warning("Suspicious activity logging failed: %s", exc)


def api_auth_required_response():
    return jsonify({"error": "authentication_required"}), 401


def enforce_admin_session() -> bool:
    admin_session_id = session.get("admin_session_id")
    if not session.get("admin_authenticated") or not admin_session_id:
        return False

    now = time.time()
    last_checked_at = float(session.get("admin_session_checked_at", 0) or 0)
    if now - last_checked_at < SESSION_CHECK_INTERVAL_SECONDS:
        return True

    try:
        init_database()
        if not admin_session_active(admin_session_id):
            safe_log_suspicious_activity(client_ip_address(), "revoked_admin_session_used", "high", None)
            session.clear()
            return False
        touch_admin_session(admin_session_id)
        session["admin_session_checked_at"] = now
        return True
    except Exception as exc:
        app.logger.warning("Admin session validation failed: %s", exc)
        return True


def admin_credentials_valid(username: str, password: str) -> bool:
    expected_username = os.getenv("ADMIN_USERNAME", "admin")
    password_hash = os.getenv("ADMIN_PASSWORD_HASH")
    plain_password = os.getenv("ADMIN_PASSWORD", "change-this-admin-password")
    if username != expected_username:
        return False
    if password_hash:
        return check_password_hash(password_hash, password)
    return password == plain_password


def login_required(view):
    @wraps(view)
    def wrapped_view(*args: Any, **kwargs: Any):
        if not enforce_admin_session():
            if request.path.startswith("/api/"):
                return api_auth_required_response()
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped_view


def selected_days() -> int:
    try:
        days = int(request.args.get("days", os.getenv("ANALYTICS_DAYS", "30")))
    except ValueError:
        days = 30
    return max(1, min(days, 365))


def json_safe(value: Any) -> Any:
    if isinstance(value, Decimal):
        return float(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    return value


@app.context_processor
def inject_context() -> dict[str, Any]:
    return {
        "target_page_labels": TARGET_PAGE_LABELS,
        "admin_name": session.get("admin_username", "Admin"),
        "current_year": time.localtime().tm_year,
        "csrf_token": csrf_token,
        "nav_sections": [
            ("Overview", [("dashboard", "Overview Dashboard", "dashboard")]),
            (
                "Analytics",
                [
                    ("analytics_page", "Page Analytics", "pages"),
                    ("analytics_page", "Careers Analytics", "careers"),
                    ("analytics_page", "Job Applications", "jobs"),
                    ("analytics_page", "Device Analytics", "devices"),
                    ("analytics_page", "Browser Analytics", "browsers"),
                    ("analytics_page", "Country Analytics", "countries"),
                    ("analytics_page", "Traffic Sources", "sources"),
                ],
            ),
            (
                "Monitoring",
                [
                    ("realtime", "Real-Time Monitoring", "realtime"),
                    ("visits", "Visitor Statistics", "visits"),
                    ("clicks", "Button Clicks", "clicks"),
                    ("conversions", "Conversions", "conversions"),
                    ("engagement", "Time Spent", "engagement"),
                    ("visitor_ips", "Visitor IP Addresses", "visitor_ips"),
                    ("logs", "Logs & Monitoring", "logs"),
                    ("security", "Security", "security"),
                ],
            ),
        ],
    }


@app.before_request
def start_request_timer() -> None:
    request._started_at = time.perf_counter()  # type: ignore[attr-defined]
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and session.get("admin_authenticated"):
        validate_csrf()


@app.after_request
def record_admin_request(response: Response) -> Response:
    if request.endpoint != "static" and session.get("admin_authenticated"):
        try:
            duration_ms = int((time.perf_counter() - getattr(request, "_started_at", time.perf_counter())) * 1000)
            log_request(
                request.method,
                request.path,
                response.status_code,
                duration_ms,
                client_ip_address(),
                request.headers.get("User-Agent"),
                session.get("admin_username"),
            )
        except Exception as exc:
            app.logger.warning("Admin request logging failed: %s", exc)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.get("/")
def root():
    if enforce_admin_session():
        return redirect(url_for("dashboard"))
    if session.get("admin_authenticated"):
        session.clear()
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if enforce_admin_session():
        return redirect(url_for("dashboard"))
    if session.get("admin_authenticated"):
        session.clear()

    if request.method == "POST":
        validate_csrf()
        if not rate_limit_login():
            flash("Too many login attempts. Please wait and try again.", "danger")
            return render_template("login.html"), 429
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if admin_credentials_valid(username, password):
            session.clear()
            session.permanent = True
            session["admin_authenticated"] = True
            session["admin_username"] = username
            session["admin_session_id"] = str(uuid.uuid4())
            session["csrf_token"] = secrets.token_urlsafe(32)
            session["admin_session_checked_at"] = time.time()
            clear_login_attempts()
            try:
                init_database()
                upsert_admin_session(
                    session["admin_session_id"],
                    username,
                    client_ip_address(),
                    request.headers.get("User-Agent"),
                )
                log_admin_activity("login_success", username, client_ip_address(), request.headers.get("User-Agent"))
            except Exception as exc:
                app.logger.warning("Admin login audit failed: %s", exc)
            return redirect(request.args.get("next") or url_for("dashboard"))
        try:
            init_database()
            log_admin_activity("login_failed", username, client_ip_address(), request.headers.get("User-Agent"))
            log_suspicious_activity(client_ip_address(), "login_failed", "low", None)
        except Exception as exc:
            app.logger.warning("Admin login failure audit failed: %s", exc)
        flash("Invalid admin username or password.", "danger")

    return render_template("login.html")


@app.post("/logout")
@login_required
def logout():
    admin_username = session.get("admin_username")
    admin_session_id = session.get("admin_session_id")
    if admin_session_id:
        try:
            revoke_admin_session(admin_session_id)
            log_admin_activity("logout", admin_username, client_ip_address(), request.headers.get("User-Agent"))
        except Exception as exc:
            app.logger.warning("Admin logout audit failed: %s", exc)
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.get("/dashboard")
@login_required
def dashboard():
    days = selected_days()
    error = None
    data: dict[str, Any] | None = None
    try:
        init_database()
        data = dashboard_data(days)
    except Exception as exc:
        error = f"Analytics database is not available: {exc}"

    return render_template("dashboard.html", dashboard=data, days=days, error=error)


@app.get("/analytics/<kind>")
@login_required
def analytics_page(kind: str):
    days = selected_days()
    error = None
    data: dict[str, Any] | None = None
    try:
        init_database()
        data = analytics_breakdown(kind, days)
    except ValueError:
        abort(404)
    except Exception as exc:
        app.logger.exception("Analytics page failed")
        error = f"Analytics database is not available: {exc}"
    return render_template("analytics_page.html", data=data, days=days, kind=kind, error=error)


@app.get("/realtime")
@login_required
def realtime():
    error = None
    data: dict[str, Any] | None = None
    try:
        init_database()
        data = realtime_data()
    except Exception as exc:
        app.logger.exception("Realtime analytics failed")
        error = f"Analytics database is not available: {exc}"
    return render_template("realtime.html", realtime=data, error=error)


@app.get("/logs")
@login_required
def logs():
    error = None
    data: dict[str, list[dict[str, Any]]] = {}
    try:
        init_database()
        data = {
            "requests": fetch_logs("requests", 100),
            "errors": fetch_logs("errors", 100),
            "suspicious": fetch_logs("suspicious", 100),
            "admin": fetch_logs("admin", 100),
        }
    except Exception as exc:
        app.logger.exception("Logs page failed")
        error = f"Logs are not available: {exc}"
    return render_template("logs.html", logs=data, error=error)


@app.get("/security")
@login_required
def security():
    password_hash_configured = bool(os.getenv("ADMIN_PASSWORD_HASH"))
    return render_template(
        "security.html",
        password_hash_configured=password_hash_configured,
        secure_cookie_enabled=app.config["SESSION_COOKIE_SECURE"],
        same_site_policy=app.config["SESSION_COOKIE_SAMESITE"],
        login_rate_limit=LOGIN_RATE_LIMIT,
        login_rate_window_seconds=LOGIN_RATE_WINDOW_SECONDS,
        session_check_interval_seconds=SESSION_CHECK_INTERVAL_SECONDS,
        generated_hash_command="python -c \"from werkzeug.security import generate_password_hash; print(generate_password_hash('your-password'))\"",
    )


@app.get("/visits")
@login_required
def visits():
    days = selected_days()
    path = request.args.get("path", "").strip()
    query = request.args.get("q", "").strip()
    error = None
    rows: list[dict[str, Any]] = []
    paths: list[str] = []
    try:
        init_database()
        rows = fetch_visits(days=days, path=path, query=query, limit=500)
        paths = distinct_paths()
    except Exception as exc:
        error = f"Analytics database is not available: {exc}"

    return render_template(
        "visits.html",
        visits=rows,
        paths=paths,
        days=days,
        path=path,
        query=query,
        error=error,
    )


@app.get("/clicks")
@login_required
def clicks():
    days = selected_days()
    query = request.args.get("q", "").strip()
    error = None
    rows: list[dict[str, Any]] = []
    summary: list[dict[str, Any]] = []
    try:
        init_database()
        rows = fetch_clicks(days=days, query=query, limit=500)
        summary = top_clicks(days=days, limit=25)
    except Exception as exc:
        error = f"Click analytics are not available: {exc}"
    return render_template("clicks.html", clicks=rows, summary=summary, days=days, query=query, error=error)


@app.get("/visitor-ips")
@login_required
def visitor_ips():
    days = selected_days()
    query = request.args.get("q", "").strip()
    error = None
    rows: list[dict[str, Any]] = []
    try:
        init_database()
        rows = visitor_ip_summary(days=days, query=query, limit=2000)
    except Exception as exc:
        error = f"Visitor IP data is not available: {exc}"
    return render_template("visitor_ips.html", visitor_ips=rows, days=days, query=query, error=error)


@app.get("/conversions")
@login_required
def conversions():
    days = selected_days()
    query = request.args.get("q", "").strip()
    error = None
    rows: list[dict[str, Any]] = []
    summary: list[dict[str, Any]] = []
    try:
        init_database()
        rows = fetch_conversions(days=days, query=query, limit=500)
        summary = conversion_summary(days=days, limit=25)
    except Exception as exc:
        error = f"Conversion analytics are not available: {exc}"
    return render_template("conversions.html", conversions=rows, summary=summary, days=days, query=query, error=error)


@app.get("/engagement")
@login_required
def engagement():
    days = selected_days()
    query = request.args.get("q", "").strip()
    error = None
    rows: list[dict[str, Any]] = []
    summary: list[dict[str, Any]] = []
    try:
        init_database()
        rows = fetch_engagement(days=days, query=query, limit=500)
        summary = engagement_summary(days=days, limit=25)
    except Exception as exc:
        error = f"Engagement analytics are not available: {exc}"
    return render_template("engagement.html", engagement=rows, summary=summary, days=days, query=query, error=error)


@app.get("/export/visits.csv")
@login_required
def export_visits():
    try:
        init_database()
    except Exception as exc:
        flash(f"Analytics database is not available: {exc}", "danger")
        return redirect(url_for("visits"))
    days = selected_days()
    path = request.args.get("path", "").strip()
    query = request.args.get("q", "").strip()
    rows = fetch_visits(days=days, path=path, query=query, limit=1000)
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "created_at",
            "ip_address",
            "path",
            "page_title",
            "status_code",
            "city",
            "region",
            "country",
            "timezone",
            "isp",
            "browser",
            "device_type",
            "referrer",
            "user_agent",
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=amtelkom-visits.csv"},
    )


@app.get("/export/clicks.csv")
@login_required
def export_clicks():
    try:
        init_database()
    except Exception as exc:
        flash(f"Click analytics are not available: {exc}", "danger")
        return redirect(url_for("clicks"))
    days = selected_days()
    query = request.args.get("q", "").strip()
    rows = fetch_clicks(days=days, query=query, limit=1000)
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "created_at",
            "session_id",
            "ip_address",
            "path",
            "page_title",
            "element_text",
            "element_type",
            "element_id",
            "element_classes",
            "target_url",
            "browser",
            "device_type",
            "referrer",
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=amtelkom-clicks.csv"},
    )


@app.get("/export/visitor-ips.csv")
@login_required
def export_visitor_ips():
    try:
        init_database()
    except Exception as exc:
        flash(f"Visitor IP data is not available: {exc}", "danger")
        return redirect(url_for("visitor_ips"))
    days = selected_days()
    query = request.args.get("q", "").strip()
    rows = visitor_ip_summary(days=days, query=query, limit=5000)
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "ip_address",
            "visits",
            "sessions",
            "first_seen_at",
            "last_seen_at",
            "city",
            "country",
            "browser",
            "device_type",
            "isp",
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=amtelkom-visitor-ips.csv"},
    )


@app.get("/export/conversions.csv")
@login_required
def export_conversions():
    try:
        init_database()
    except Exception as exc:
        flash(f"Conversion analytics are not available: {exc}", "danger")
        return redirect(url_for("conversions"))
    days = selected_days()
    query = request.args.get("q", "").strip()
    rows = fetch_conversions(days=days, query=query, limit=1000)
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "created_at",
            "session_id",
            "ip_address",
            "conversion_type",
            "path",
            "page_title",
            "target",
            "value_label",
            "browser",
            "device_type",
            "referrer",
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=amtelkom-conversions.csv"},
    )


@app.get("/export/engagement.csv")
@login_required
def export_engagement():
    try:
        init_database()
    except Exception as exc:
        flash(f"Engagement analytics are not available: {exc}", "danger")
        return redirect(url_for("engagement"))
    days = selected_days()
    query = request.args.get("q", "").strip()
    rows = fetch_engagement(days=days, query=query, limit=1000)
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "created_at",
            "session_id",
            "ip_address",
            "path",
            "page_title",
            "active_seconds",
            "max_scroll_percent",
            "browser",
            "device_type",
        ],
        extrasaction="ignore",
    )
    writer.writeheader()
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=amtelkom-engagement.csv"},
    )


@app.get("/api/overview")
@login_required
def api_overview():
    days = selected_days()
    init_database()
    return jsonify(json_safe(dashboard_data(days)))


@app.get("/api/realtime")
@login_required
def api_realtime():
    init_database()
    return jsonify(json_safe(realtime_data()))


@app.get("/api/analytics/<kind>")
@login_required
def api_analytics(kind: str):
    days = selected_days()
    init_database()
    try:
        return jsonify(json_safe(analytics_breakdown(kind, days)))
    except ValueError:
        abort(404)


@app.get("/api/reports")
@login_required
def api_reports():
    days = selected_days()
    init_database()
    return jsonify(json_safe(report_data(days)))


@app.get("/api/clicks")
@login_required
def api_clicks():
    days = selected_days()
    query = request.args.get("q", "").strip()
    init_database()
    return jsonify(json_safe({"summary": top_clicks(days), "clicks": fetch_clicks(days, query=query)}))


@app.get("/api/conversions")
@login_required
def api_conversions():
    days = selected_days()
    query = request.args.get("q", "").strip()
    init_database()
    return jsonify(json_safe({"summary": conversion_summary(days), "conversions": fetch_conversions(days, query=query)}))


@app.get("/api/engagement")
@login_required
def api_engagement():
    days = selected_days()
    query = request.args.get("q", "").strip()
    init_database()
    return jsonify(json_safe({"summary": engagement_summary(days), "engagement": fetch_engagement(days, query=query)}))


@app.get("/api/visitor-ips")
@login_required
def api_visitor_ips():
    days = selected_days()
    query = request.args.get("q", "").strip()
    init_database()
    return jsonify(json_safe(visitor_ip_summary(days, query=query)))


@app.errorhandler(Exception)
def handle_exception(exc: Exception):
    if getattr(exc, "code", None):
        return exc
    app.logger.exception("Unhandled admin application error")
    try:
        log_error("error", str(exc), request.path, traceback.format_exc())
    except Exception:
        pass
    return render_template("error.html", error=exc), 500


@app.cli.command("aggregate-analytics")
def aggregate_analytics_command() -> None:
    init_database()
    changed_rows = refresh_analytics_aggregates()
    print(f"Analytics aggregates refreshed ({changed_rows} rows changed).")


@app.cli.group("db")
def db_cli() -> None:
    """Database management commands for AMTEL admin analytics."""


@db_cli.command("upgrade")
def db_upgrade_command() -> None:
    """Create or upgrade the MySQL analytics schema."""
    init_database()
    click.echo("Database schema is up to date.")


@db_cli.command("init")
def db_init_command() -> None:
    """Initialize the MySQL analytics schema."""
    init_database()
    click.echo("Database schema initialized.")


@db_cli.command("status")
def db_status_command() -> None:
    """Check whether the analytics database is reachable."""
    try:
        init_database()
    except Exception as error:
        raise click.ClickException(f"Database is not available: {error}") from error
    click.echo("Database connection and schema check passed.")


if __name__ == "__main__":
    init_database()
    app.run(host=os.getenv("ADMIN_HOST", "127.0.0.1"), port=int(os.getenv("ADMIN_PORT", "5001")), debug=True)
