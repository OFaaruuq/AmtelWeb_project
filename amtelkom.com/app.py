from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any

import click
from dotenv import load_dotenv
from flask import Flask, abort, flash, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash

from analytics import (
    TARGET_PAGE_LABELS,
    analytics_error_message,
    empty_dashboard_data,
    get_dashboard_data,
    init_analytics_db,
    record_click,
    record_conversion,
    record_engagement,
    record_visit,
)
from data.jobs import JOBS, get_open_jobs, get_job


BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"
STATIC_DIR = BASE_DIR / "static"

load_dotenv(BASE_DIR / ".env")

LEGACY_PAGES = {
    "404.html",
    "about.html",
    "appointment.html",
    "blog.html",
    "courses.html",
    "feature.html",
    "index.html",
    "team.html",
    "terms.html",
    "testimonial.html",
    "google734e5d615b5bf88a.html",
}

LEGACY_URL_REDIRECTS = {
    "index.html": "/",
    "about.html": "/about",
    "appointment.html": "/appointment",
    "blog.html": "/blog",
    "career.html": "/careers",
    "contact.html": "/contact",
    "courses.html": "/courses",
    "feature.html": "/features",
    "team.html": "/team",
    "terms.html": "/terms",
    "testimonial.html": "/testimonials",
}

ASSET_FOLDERS = {"css", "img", "js", "lib"}

MY_SMS_HERO = {
    "eyebrow": "MY SMS PLATFORM",
    "title": "The simplest way to stay connected",
    "lead": "Engage, track, and grow your audiences with AMTEL's My SMS Platform.",
    "description": (
        "We have got the tech in hand, so you can concentrate on your customers. "
        "Build your personalized message, choose your Somali based audience, and "
        "understand your reach using the analytics function."
    ),
}


app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "change-me-in-production")
app.config["ANALYTICS_READY"] = False

# Compatibility alias for shared setup commands and operational scripts.
init_database = init_analytics_db


def setup_analytics() -> None:
    try:
        init_analytics_db()
        app.config["ANALYTICS_READY"] = True
    except Exception as error:  # Analytics should never prevent the public site from loading.
        app.config["ANALYTICS_READY"] = False
        app.logger.warning("Analytics database setup failed: %s", error)


@app.cli.group("db")
def db_cli() -> None:
    """Database management commands for AMTEL analytics."""


@db_cli.command("upgrade")
def db_upgrade_command() -> None:
    """Create or upgrade the MySQL analytics schema."""
    init_analytics_db()
    app.config["ANALYTICS_READY"] = True
    click.echo("Database schema is up to date.")


@db_cli.command("init")
def db_init_command() -> None:
    """Initialize the MySQL analytics schema."""
    init_analytics_db()
    app.config["ANALYTICS_READY"] = True
    click.echo("Database schema initialized.")


@db_cli.command("status")
def db_status_command() -> None:
    """Check whether the analytics database is reachable."""
    try:
        init_analytics_db()
    except Exception as error:
        raise click.ClickException(f"Database is not available: {error}") from error
    click.echo("Database connection and schema check passed.")


def admin_credentials_valid(username: str, password: str) -> bool:
    expected_username = os.getenv("ADMIN_USERNAME", "admin")
    password_hash = os.getenv("ADMIN_PASSWORD_HASH")
    plain_password = os.getenv("ADMIN_PASSWORD", "change-this-admin-password")

    if username != expected_username:
        return False
    if password_hash:
        return check_password_hash(password_hash, password)
    return password == plain_password


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)

    return wrapped_view


def client_ip_address() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.headers.get("X-Real-IP") or request.remote_addr or "0.0.0.0"


def browser_name(user_agent: str) -> str:
    lowered = user_agent.lower()
    if "edg/" in lowered:
        return "Microsoft Edge"
    if "opr/" in lowered or "opera" in lowered:
        return "Opera"
    if "chrome/" in lowered and "chromium" not in lowered:
        return "Chrome"
    if "firefox/" in lowered:
        return "Firefox"
    if "safari/" in lowered and "chrome/" not in lowered:
        return "Safari"
    if "bot" in lowered or "crawler" in lowered or "spider" in lowered:
        return "Bot"
    return "Unknown"


def device_type(user_agent: str) -> str:
    lowered = user_agent.lower()
    if "bot" in lowered or "crawler" in lowered or "spider" in lowered:
        return "Bot"
    if "tablet" in lowered or "ipad" in lowered:
        return "Tablet"
    if "mobile" in lowered or "android" in lowered or "iphone" in lowered:
        return "Mobile"
    return "Desktop"


def should_track_request(response) -> bool:
    if not app.config.get("ANALYTICS_READY"):
        return False
    if request.method != "GET":
        return False
    if response.status_code >= 500:
        return False
    if request.path.startswith(("/admin", "/css/", "/img/", "/js/", "/lib/")):
        return False
    if request.path in {"/favicon.ico", "/robots.txt"}:
        return False
    return "text/html" in response.content_type


@app.after_request
def track_visitor(response):
    if not should_track_request(response):
        return response

    user_agent = request.headers.get("User-Agent", "")
    current_session_id = visitor_session_id()
    event = {
        "session_id": current_session_id,
        "ip_address": client_ip_address(),
        "path": request.path,
        "page_title": TARGET_PAGE_LABELS.get(request.path, request.path.strip("/") or "Home"),
        "endpoint": request.endpoint,
        "method": request.method,
        "status_code": response.status_code,
        "referrer": request.referrer,
        "user_agent": user_agent,
        "browser": browser_name(user_agent),
        "device_type": device_type(user_agent),
    }

    try:
        record_visit(event)
    except Exception as error:
        app.logger.warning("Visitor analytics write failed: %s", error)

    response.set_cookie(
        "amtelkom_session_id",
        current_session_id,
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        samesite="Lax",
    )
    return response


def append_jsonl(filename: str, payload: dict[str, Any]) -> None:
    INSTANCE_DIR.mkdir(exist_ok=True)
    record = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    with (INSTANCE_DIR / filename).open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=True) + "\n")


def visitor_session_id() -> str:
    cached_session_id = getattr(request, "_amtelkom_session_id", None)
    if cached_session_id:
        return cached_session_id
    cached_session_id = request.cookies.get("amtelkom_session_id") or str(uuid.uuid4())
    request._amtelkom_session_id = cached_session_id  # type: ignore[attr-defined]
    return cached_session_id


def analytics_base_event(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    user_agent = request.headers.get("User-Agent", "")
    return {
        "session_id": visitor_session_id(),
        "ip_address": client_ip_address(),
        "path": str(payload.get("path") or request.path or "/")[:255],
        "page_title": str(payload.get("page_title") or "")[:255],
        "referrer": request.headers.get("Referer"),
        "user_agent": user_agent,
        "browser": browser_name(user_agent),
        "device_type": device_type(user_agent),
    }


def analytics_json_response(payload: dict[str, Any], status: int = 200):
    response = app.response_class(response=json.dumps(payload), status=status, mimetype="application/json")
    response.set_cookie(
        "amtelkom_session_id",
        visitor_session_id(),
        max_age=60 * 60 * 24 * 30,
        httponly=True,
        samesite="Lax",
    )
    return response


def track_conversion(conversion_type: str, target: str = "", value_label: str = "") -> None:
    if not app.config.get("ANALYTICS_READY"):
        return
    event = {
        **analytics_base_event({"path": request.path, "page_title": request.endpoint or request.path}),
        "conversion_type": conversion_type,
        "target": target,
        "value_label": value_label,
    }
    try:
        record_conversion(event)
    except Exception as error:
        app.logger.warning("Conversion analytics write failed: %s", error)


@app.context_processor
def inject_site_context() -> dict[str, Any]:
    return {
        "site": {
            "name": "AMTEL Ltd",
            "phone": "+252 71 0000000",
            "email": "info@amtelkom.com",
            "support_email": "support@amtelkom.com",
            "recruitment_email": "recruitment@amtelkom.com",
            "address": "Amal Plaza, Bakaro Market, Mogadishu, Somalia",
            "hours": "Sat - Thu : 12.00 AM - 12.00 PM",
        }
    }


@app.get("/")
def home():
    return render_template("index.html", active_page="home")


@app.get("/careers")
def careers():
    return render_template("career.html", active_page="career", jobs=get_open_jobs())


@app.get("/mysms")
def mysms():
    return render_template("mysms.html", active_page="mysms", hero=MY_SMS_HERO)


@app.route("/contact.html", methods=["GET", "POST"])
def legacy_contact():
    if request.method == "POST":
        return contact()
    return redirect(url_for("contact"), code=301)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        append_jsonl(
            "contact_messages.jsonl",
            {
                "name": request.form.get("name", "").strip(),
                "email": email,
                "message": request.form.get("comment", "").strip(),
            },
        )
        track_conversion("contact_form", target=email, value_label="Contact form")
        flash("Thank you for your message. We will get back to you soon.", "success")
        return redirect(url_for("contact"))

    return render_template("contact.html", active_page="contact")


@app.get("/about")
def about():
    return render_template("about.html", active_page="about")


@app.get("/appointment")
def appointment():
    return render_template("appointment.html", active_page="appointment")


@app.get("/blog")
def blog():
    return render_template("blog.html", active_page="blog")


@app.get("/courses")
def courses():
    return render_template("courses.html", active_page="courses")


@app.get("/features")
def features():
    return render_template("feature.html", active_page="features")


@app.get("/team")
def team():
    return render_template("team.html", active_page="team")


@app.get("/terms")
def terms():
    return render_template("terms.html", active_page="terms")


@app.get("/testimonials")
def testimonials():
    return render_template("testimonial.html", active_page="testimonials")


@app.post("/newsletter")
def newsletter():
    email = request.form.get("email", "").strip()
    if email:
        append_jsonl("newsletter_subscribers.jsonl", {"email": email})
        track_conversion("newsletter_signup", target=email, value_label="Newsletter")
        flash("Thank you for subscribing.", "success")
    return redirect(request.referrer or url_for("home"))


@app.post("/analytics/click")
def analytics_click():
    if not app.config.get("ANALYTICS_READY"):
        return {"ok": False}, 503

    payload = request.get_json(silent=True) or {}
    event = {
        **analytics_base_event(payload),
        "path": str(payload.get("path") or request.headers.get("Referer") or "/")[:255],
        "element_text": str(payload.get("element_text") or "")[:255],
        "element_type": str(payload.get("element_type") or "")[:80],
        "element_id": str(payload.get("element_id") or "")[:120],
        "element_classes": str(payload.get("element_classes") or "")[:255],
        "target_url": str(payload.get("target_url") or ""),
    }
    try:
        record_click(event)
    except Exception as error:
        app.logger.warning("Click analytics write failed: %s", error)
        return {"ok": False}, 500

    return analytics_json_response({"ok": True})


@app.post("/analytics/engagement")
def analytics_engagement():
    if not app.config.get("ANALYTICS_READY"):
        return {"ok": False}, 503

    payload = request.get_json(silent=True) or {}
    event = {
        **analytics_base_event(payload),
        "active_seconds": payload.get("active_seconds"),
        "max_scroll_percent": payload.get("max_scroll_percent"),
    }
    try:
        record_engagement(event)
    except Exception as error:
        app.logger.warning("Engagement analytics write failed: %s", error)
        return {"ok": False}, 500
    return analytics_json_response({"ok": True})


@app.post("/analytics/conversion")
def analytics_conversion():
    if not app.config.get("ANALYTICS_READY"):
        return {"ok": False}, 503

    payload = request.get_json(silent=True) or {}
    event = {
        **analytics_base_event(payload),
        "conversion_type": str(payload.get("conversion_type") or "unknown")[:80],
        "target": str(payload.get("target") or "")[:255],
        "value_label": str(payload.get("value_label") or "")[:255],
    }
    try:
        record_conversion(event)
    except Exception as error:
        app.logger.warning("Conversion analytics write failed: %s", error)
        return {"ok": False}, 500
    return analytics_json_response({"ok": True})


@app.get("/jobs/<slug>")
def job_detail(slug: str):
    job = get_job(slug)
    if job is None:
        abort(404)
    return render_template("job_detail.html", active_page="career", job=job)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    return redirect(os.getenv("ADMIN_APP_URL", "http://127.0.0.1:5001"))


@app.post("/admin/logout")
@admin_required
def admin_logout():
    session.clear()
    return redirect(os.getenv("ADMIN_APP_URL", "http://127.0.0.1:5001"))


@app.get("/admin")
@app.get("/admin/dashboard")
@admin_required
def admin_dashboard():
    return redirect(os.getenv("ADMIN_APP_URL", "http://127.0.0.1:5001"))


@app.get("/<path:filename>")
def legacy_or_asset(filename: str):
    first_segment = filename.split("/", 1)[0]
    if first_segment in ASSET_FOLDERS:
        return send_from_directory(STATIC_DIR, filename)

    if filename.startswith("job-") and filename.endswith(".html"):
        slug = filename.removeprefix("job-").removesuffix(".html")
        return redirect(url_for("job_detail", slug=slug), code=301)

    if filename == "mysms.html":
        return redirect(url_for("mysms"), code=301)

    if filename in LEGACY_URL_REDIRECTS:
        return redirect(LEGACY_URL_REDIRECTS[filename], code=301)

    if filename in LEGACY_PAGES:
        return render_template(filename)

    abort(404)


@app.errorhandler(404)
def not_found(_error):
    legacy_404 = BASE_DIR / "templates" / "404.html"
    if legacy_404.exists():
        return render_template("404.html"), 404
    return render_template("404.html"), 404


setup_analytics()


if __name__ == "__main__":
    app.run(debug=True)
