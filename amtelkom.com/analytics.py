from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

import mysql.connector
import requests


TARGET_PAGE_LABELS = {
    "/": "Index page",
    "/index.html": "Index page",
    "/careers": "Careers page",
    "/career.html": "Careers page",
    "/contact": "Contact page",
    "/about": "About page",
    "/terms": "Terms page",
    "/mysms": "My SMS page",
    "/job-oss-bss-engineer.html": "OSS/BSS Engineer job page",
    "/jobs/oss-bss-engineer": "OSS/BSS Engineer job page",
}

TARGET_PATHS = set(TARGET_PAGE_LABELS)
SESSION_IDLE_MINUTES = 30

KNOWN_BOT_PATTERNS = {
    "google": "Google",
    "googlebot": "Google",
    "bingbot": "Microsoft Bing",
    "bingpreview": "Microsoft Bing",
    "msnbot": "Microsoft",
    "semrush": "SEMrush",
    "amazonbot": "Amazon",
    "ahrefs": "Ahrefs",
    "mj12bot": "Majestic",
    "dotbot": "Dotbot",
    "yandex": "Yandex",
    "baiduspider": "Baidu",
}
BOT_USER_AGENT_TOKENS = (
    "bot",
    "crawl",
    "crawler",
    "spider",
    "slurp",
    "scrape",
    "monitor",
    "preview",
    "headless",
)
DATACENTER_ISP_TOKENS = (
    "amazon",
    "aws",
    "microsoft",
    "azure",
    "google cloud",
    "google llc",
    "digitalocean",
    "linode",
    "akamai",
    "ovh",
    "hetzner",
    "contabo",
    "vultr",
    "cloudflare",
    "leaseweb",
    "choopa",
    "oracle",
    "alibaba",
    "tencent",
)


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if value is None or value == "":
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def _env_bool(name: str, default: str = "true") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _known_bot_name(user_agent: str, isp: str | None = None) -> str | None:
    fingerprint = f"{user_agent} {isp or ''}".lower()
    for token, bot_name in KNOWN_BOT_PATTERNS.items():
        if token in fingerprint:
            return bot_name
    return None


def _is_datacenter_isp(isp: str | None) -> bool:
    lowered = (isp or "").lower()
    return any(token in lowered for token in DATACENTER_ISP_TOKENS)


def classify_visit(
    user_agent: str | None,
    browser: str | None,
    device_type: str | None,
    isp: str | None,
    recent_ip_requests: int = 0,
) -> dict[str, Any]:
    ua = user_agent or ""
    ua_lower = ua.lower()
    reasons: list[str] = []
    risk_score = 0
    bot_name = _known_bot_name(ua, isp)

    if bot_name:
        reasons.append(f"known bot: {bot_name}")
        risk_score = max(risk_score, 100)

    if any(token in ua_lower for token in BOT_USER_AGENT_TOKENS):
        reasons.append("bot-like user agent")
        risk_score = max(risk_score, 50)
        bot_name = bot_name or "Generic crawler"

    datacenter_ip = _is_datacenter_isp(isp)
    if datacenter_ip:
        reasons.append("datacenter network")
        risk_score = max(risk_score, 30)

    if recent_ip_requests >= 60:
        reasons.append("high-frequency requests")
        risk_score = max(risk_score, 70)

    if (browser or "").lower() == "bot" or (device_type or "").lower() == "bot":
        reasons.append("bot device/browser signature")
        risk_score = max(risk_score, 50)
        bot_name = bot_name or "Generic crawler"

    looks_human_browser = any(token in ua_lower for token in ("mobile safari", "chrome/", "firefox/", "safari/"))
    if bot_name or risk_score >= 100:
        classification = "bot"
    elif risk_score >= 70 or (datacenter_ip and recent_ip_requests >= 10):
        classification = "suspicious"
    elif datacenter_ip:
        classification = "suspicious"
    elif not isp and recent_ip_requests >= 10:
        classification = "suspicious"
        reasons.append("unknown network with repeated requests")
        risk_score = max(risk_score, 40)
    elif looks_human_browser:
        classification = "human"
        reasons.append("normal browser signature")
    else:
        classification = "human"
        reasons.append("no bot indicators")

    if classification == "bot":
        risk_score = max(risk_score, 100)

    return {
        "visitor_classification": classification,
        "is_bot": classification == "bot",
        "bot_name": bot_name,
        "risk_score": min(risk_score, 100),
        "classification_reason": "; ".join(dict.fromkeys(reasons))[:255],
    }


def _mysql_config(include_database: bool = True) -> dict[str, Any]:
    config: dict[str, Any] = {
        "host": _required_env("MYSQL_HOST"),
        "port": int(_required_env("MYSQL_PORT")),
        "user": _required_env("MYSQL_USER"),
        "password": os.getenv("MYSQL_PASSWORD", ""),
        "connection_timeout": int(_required_env("MYSQL_CONNECTION_TIMEOUT")),
        "autocommit": False,
    }
    if include_database:
        config["database"] = _required_env("MYSQL_DATABASE")
    return config


def _execute_optional_schema_change(cursor: Any, statement: str) -> None:
    try:
        cursor.execute(statement)
    except mysql.connector.Error as exc:
        if exc.errno not in {1060, 1061}:  # duplicate column or duplicate key name
            raise


@contextmanager
def mysql_connection(dictionary: bool = False) -> Iterator[mysql.connector.MySQLConnection]:
    connection = mysql.connector.connect(**_mysql_config())
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_analytics_db() -> None:
    database_name = _required_env("MYSQL_DATABASE")
    connection = mysql.connector.connect(**_mysql_config(include_database=False))
    cursor = connection.cursor()
    try:
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{database_name}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        cursor.execute(f"USE `{database_name}`")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ip_location_cache (
                ip_address VARCHAR(45) PRIMARY KEY,
                country VARCHAR(120),
                region VARCHAR(120),
                city VARCHAR(120),
                timezone VARCHAR(120),
                isp VARCHAR(255),
                latitude DECIMAL(10, 7),
                longitude DECIMAL(10, 7),
                raw_payload JSON NULL,
                updated_at DATETIME(6) NOT NULL
            ) ENGINE=InnoDB
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS visitor_events (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                visit_uuid CHAR(36) NOT NULL,
                created_at DATETIME(6) NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                ip_hash CHAR(64) NOT NULL,
                path VARCHAR(255) NOT NULL,
                page_title VARCHAR(255) NOT NULL,
                endpoint VARCHAR(120),
                method VARCHAR(16) NOT NULL,
                status_code SMALLINT UNSIGNED NOT NULL,
                referrer TEXT,
                user_agent TEXT,
                browser VARCHAR(80),
                device_type VARCHAR(40),
                visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human',
                is_bot BOOLEAN NOT NULL DEFAULT FALSE,
                bot_name VARCHAR(120),
                risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
                classification_reason VARCHAR(255),
                country VARCHAR(120),
                region VARCHAR(120),
                city VARCHAR(120),
                timezone VARCHAR(120),
                isp VARCHAR(255),
                latitude DECIMAL(10, 7),
                longitude DECIMAL(10, 7),
                is_target_page BOOLEAN NOT NULL DEFAULT FALSE,
                INDEX idx_created_at (created_at),
                INDEX idx_path_created_at (path, created_at),
                INDEX idx_ip_created_at (ip_hash, created_at),
                INDEX idx_target_created_at (is_target_page, created_at),
                INDEX idx_class_created_at (visitor_classification, created_at),
                INDEX idx_bot_created_at (is_bot, created_at)
            ) ENGINE=InnoDB
            """
        )
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN session_id CHAR(36) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN time_spent_seconds INT UNSIGNED NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human'")
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN is_bot BOOLEAN NOT NULL DEFAULT FALSE")
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN bot_name VARCHAR(120) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0")
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN classification_reason VARCHAR(255) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD INDEX idx_session_created_at (session_id, created_at)")
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD INDEX idx_class_created_at (visitor_classification, created_at)")
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD INDEX idx_bot_created_at (is_bot, created_at)")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS visitor_sessions (
                session_id CHAR(36) NOT NULL PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL,
                ip_hash CHAR(64) NOT NULL,
                started_at DATETIME(6) NOT NULL,
                ended_at DATETIME(6) NOT NULL,
                duration_seconds INT UNSIGNED NOT NULL DEFAULT 0,
                page_views INT UNSIGNED NOT NULL DEFAULT 0,
                unique_pages INT UNSIGNED NOT NULL DEFAULT 0,
                visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human',
                is_bot BOOLEAN NOT NULL DEFAULT FALSE,
                bot_name VARCHAR(120),
                risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
                classification_reason VARCHAR(255),
                user_agent TEXT,
                browser VARCHAR(80),
                device_type VARCHAR(40),
                country VARCHAR(120),
                region VARCHAR(120),
                city VARCHAR(120),
                timezone VARCHAR(120),
                isp VARCHAR(255),
                INDEX idx_sessions_started (started_at),
                INDEX idx_sessions_ended (ended_at),
                INDEX idx_sessions_ip_started (ip_hash, started_at),
                INDEX idx_sessions_class_started (visitor_classification, started_at),
                INDEX idx_sessions_bot_started (is_bot, started_at)
            ) ENGINE=InnoDB
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS bot_activity_logs (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                created_at DATETIME(6) NOT NULL,
                session_id CHAR(36),
                ip_address VARCHAR(45) NOT NULL,
                ip_hash CHAR(64) NOT NULL,
                path VARCHAR(255) NOT NULL,
                bot_name VARCHAR(120),
                visitor_classification VARCHAR(20) NOT NULL,
                risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
                classification_reason VARCHAR(255),
                user_agent TEXT,
                isp VARCHAR(255),
                details JSON NULL,
                INDEX idx_bot_logs_created (created_at),
                INDEX idx_bot_logs_ip_created (ip_hash, created_at),
                INDEX idx_bot_logs_class_created (visitor_classification, created_at)
            ) ENGINE=InnoDB
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS click_events (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                click_uuid CHAR(36) NOT NULL,
                created_at DATETIME(6) NOT NULL,
                session_id CHAR(36),
                ip_address VARCHAR(45) NOT NULL,
                ip_hash CHAR(64) NOT NULL,
                path VARCHAR(255) NOT NULL,
                page_title VARCHAR(255),
                element_text VARCHAR(255),
                element_type VARCHAR(80),
                element_id VARCHAR(120),
                element_classes VARCHAR(255),
                target_url TEXT,
                referrer TEXT,
                user_agent TEXT,
                browser VARCHAR(80),
                device_type VARCHAR(40),
                visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human',
                is_bot BOOLEAN NOT NULL DEFAULT FALSE,
                bot_name VARCHAR(120),
                risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
                classification_reason VARCHAR(255),
                isp VARCHAR(255),
                INDEX idx_click_created_at (created_at),
                INDEX idx_click_path_created_at (path, created_at),
                INDEX idx_click_ip_created_at (ip_hash, created_at),
                INDEX idx_click_session_created_at (session_id, created_at),
                INDEX idx_click_element_text (element_text, created_at),
                INDEX idx_click_class_created (visitor_classification, created_at)
            ) ENGINE=InnoDB
            """
        )
        _execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human'")
        _execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN is_bot BOOLEAN NOT NULL DEFAULT FALSE")
        _execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN bot_name VARCHAR(120) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0")
        _execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN classification_reason VARCHAR(255) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN isp VARCHAR(255) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD INDEX idx_click_class_created (visitor_classification, created_at)")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS page_engagement_events (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                engagement_uuid CHAR(36) NOT NULL,
                created_at DATETIME(6) NOT NULL,
                session_id CHAR(36),
                ip_address VARCHAR(45) NOT NULL,
                ip_hash CHAR(64) NOT NULL,
                path VARCHAR(255) NOT NULL,
                page_title VARCHAR(255),
                active_seconds INT UNSIGNED NOT NULL DEFAULT 0,
                max_scroll_percent TINYINT UNSIGNED NOT NULL DEFAULT 0,
                user_agent TEXT,
                browser VARCHAR(80),
                device_type VARCHAR(40),
                visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human',
                is_bot BOOLEAN NOT NULL DEFAULT FALSE,
                bot_name VARCHAR(120),
                risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
                classification_reason VARCHAR(255),
                isp VARCHAR(255),
                INDEX idx_engagement_created_at (created_at),
                INDEX idx_engagement_path_created_at (path, created_at),
                INDEX idx_engagement_ip_created_at (ip_hash, created_at),
                INDEX idx_engagement_session_created_at (session_id, created_at),
                INDEX idx_engagement_class_created (visitor_classification, created_at)
            ) ENGINE=InnoDB
            """
        )
        _execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human'")
        _execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN is_bot BOOLEAN NOT NULL DEFAULT FALSE")
        _execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN bot_name VARCHAR(120) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0")
        _execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN classification_reason VARCHAR(255) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN isp VARCHAR(255) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD INDEX idx_engagement_class_created (visitor_classification, created_at)")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS conversion_events (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                conversion_uuid CHAR(36) NOT NULL,
                created_at DATETIME(6) NOT NULL,
                session_id CHAR(36),
                ip_address VARCHAR(45) NOT NULL,
                ip_hash CHAR(64) NOT NULL,
                conversion_type VARCHAR(80) NOT NULL,
                path VARCHAR(255) NOT NULL,
                page_title VARCHAR(255),
                target VARCHAR(255),
                value_label VARCHAR(255),
                referrer TEXT,
                user_agent TEXT,
                browser VARCHAR(80),
                device_type VARCHAR(40),
                visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human',
                is_bot BOOLEAN NOT NULL DEFAULT FALSE,
                bot_name VARCHAR(120),
                risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0,
                classification_reason VARCHAR(255),
                isp VARCHAR(255),
                INDEX idx_conversion_created_at (created_at),
                INDEX idx_conversion_type_created_at (conversion_type, created_at),
                INDEX idx_conversion_ip_created_at (ip_hash, created_at),
                INDEX idx_conversion_session_created_at (session_id, created_at),
                INDEX idx_conversion_class_created (visitor_classification, created_at)
            ) ENGINE=InnoDB
            """
        )
        _execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human'")
        _execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN is_bot BOOLEAN NOT NULL DEFAULT FALSE")
        _execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN bot_name VARCHAR(120) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0")
        _execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN classification_reason VARCHAR(255) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN isp VARCHAR(255) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD INDEX idx_conversion_class_created (visitor_classification, created_at)")
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()


def _hash_ip(ip_address: str) -> str:
    salt = os.getenv("ANALYTICS_IP_HASH_SALT", "replace-this-salt")
    return hashlib.sha256(f"{salt}:{ip_address}".encode("utf-8")).hexdigest()


def _empty_location() -> dict[str, Any]:
    return {
        "country": None,
        "region": None,
        "city": None,
        "timezone": None,
        "isp": None,
        "latitude": None,
        "longitude": None,
    }


def _is_public_ip(ip_address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip_address)
    except ValueError:
        return False
    return parsed.is_global


def _cached_location(ip_address: str) -> dict[str, Any] | None:
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT country, region, city, timezone, isp, latitude, longitude
                FROM ip_location_cache
                WHERE ip_address = %s
                """,
                (ip_address,),
            )
            return cursor.fetchone()
        finally:
            cursor.close()


def _save_location(ip_address: str, location: dict[str, Any]) -> None:
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO ip_location_cache (
                    ip_address, country, region, city, timezone, isp,
                    latitude, longitude, raw_payload, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    country = VALUES(country),
                    region = VALUES(region),
                    city = VALUES(city),
                    timezone = VALUES(timezone),
                    isp = VALUES(isp),
                    latitude = VALUES(latitude),
                    longitude = VALUES(longitude),
                    raw_payload = VALUES(raw_payload),
                    updated_at = VALUES(updated_at)
                """,
                (
                    ip_address,
                    location.get("country"),
                    location.get("region"),
                    location.get("city"),
                    location.get("timezone"),
                    location.get("isp"),
                    location.get("latitude"),
                    location.get("longitude"),
                    location.get("raw_payload"),
                    datetime.now(timezone.utc).replace(tzinfo=None),
                ),
            )
        finally:
            cursor.close()


def lookup_ip_location(ip_address: str) -> dict[str, Any]:
    empty = _empty_location()
    if not _env_bool("GEOLOCATION_ENABLED", "true") or not _is_public_ip(ip_address):
        return empty

    cached = _cached_location(ip_address)
    if cached:
        return cached

    endpoint = os.getenv("GEOLOCATION_ENDPOINT", "http://ip-api.com/json/{ip}")
    response = requests.get(endpoint.format(ip=ip_address), timeout=2.5)
    response.raise_for_status()
    payload = response.json()
    if payload.get("status") == "fail":
        return empty

    location = {
        "country": payload.get("country"),
        "region": payload.get("regionName") or payload.get("region"),
        "city": payload.get("city"),
        "timezone": payload.get("timezone"),
        "isp": payload.get("isp") or payload.get("org"),
        "latitude": payload.get("lat"),
        "longitude": payload.get("lon"),
        "raw_payload": response.text,
    }
    _save_location(ip_address, location)
    return {key: location.get(key) for key in empty}


def _recent_ip_request_count(cursor: Any, ip_hash: str, now: datetime) -> int:
    cursor.execute(
        """
        SELECT COUNT(*)
        FROM visitor_events
        WHERE ip_hash = %s AND created_at >= %s
        """,
        (ip_hash, now - timedelta(minutes=5)),
    )
    row = cursor.fetchone()
    return int((row[0] if row else 0) or 0)


def _upsert_visitor_session(
    cursor: Any,
    session_id: str | None,
    event: dict[str, Any],
    ip_hash: str,
    now: datetime,
    location: dict[str, Any],
    intelligence: dict[str, Any],
) -> None:
    if not session_id:
        return
    cursor.execute(
        """
        SELECT COUNT(DISTINCT path)
        FROM visitor_events
        WHERE session_id = %s
        """,
        (session_id,),
    )
    row = cursor.fetchone()
    previous_unique_pages = int((row[0] if row else 0) or 0)
    unique_pages = previous_unique_pages
    cursor.execute(
        """
        SELECT 1
        FROM visitor_events
        WHERE session_id = %s AND path = %s
        LIMIT 1
        """,
        (session_id, event.get("path") or "/"),
    )
    if cursor.fetchone():
        unique_pages = previous_unique_pages

    cursor.execute(
        """
        INSERT INTO visitor_sessions (
            session_id, ip_address, ip_hash, started_at, ended_at, duration_seconds,
            page_views, unique_pages, visitor_classification, is_bot, bot_name,
            risk_score, classification_reason, user_agent, browser, device_type,
            country, region, city, timezone, isp
        )
        VALUES (
            %s, %s, %s, %s, %s, 0, 1, 1, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s
        )
        ON DUPLICATE KEY UPDATE
            ended_at = VALUES(ended_at),
            duration_seconds = TIMESTAMPDIFF(SECOND, started_at, VALUES(ended_at)),
            page_views = page_views + 1,
            unique_pages = %s,
            visitor_classification = CASE
                WHEN VALUES(is_bot) = 1 THEN VALUES(visitor_classification)
                WHEN visitor_classification = 'bot' THEN visitor_classification
                WHEN VALUES(risk_score) > risk_score THEN VALUES(visitor_classification)
                ELSE visitor_classification
            END,
            is_bot = is_bot OR VALUES(is_bot),
            bot_name = COALESCE(VALUES(bot_name), bot_name),
            risk_score = GREATEST(risk_score, VALUES(risk_score)),
            classification_reason = COALESCE(VALUES(classification_reason), classification_reason),
            user_agent = VALUES(user_agent),
            browser = VALUES(browser),
            device_type = VALUES(device_type),
            country = VALUES(country),
            region = VALUES(region),
            city = VALUES(city),
            timezone = VALUES(timezone),
            isp = VALUES(isp)
        """,
        (
            session_id,
            event.get("ip_address") or "0.0.0.0",
            ip_hash,
            now,
            now,
            intelligence["visitor_classification"],
            intelligence["is_bot"],
            intelligence.get("bot_name"),
            intelligence["risk_score"],
            intelligence.get("classification_reason"),
            event.get("user_agent"),
            event.get("browser"),
            event.get("device_type"),
            location.get("country"),
            location.get("region"),
            location.get("city"),
            location.get("timezone"),
            location.get("isp"),
            unique_pages,
        ),
    )


def _log_bot_activity(
    cursor: Any,
    event: dict[str, Any],
    ip_hash: str,
    now: datetime,
    location: dict[str, Any],
    intelligence: dict[str, Any],
) -> None:
    if intelligence["visitor_classification"] == "human":
        return
    cursor.execute(
        """
        INSERT INTO bot_activity_logs (
            created_at, session_id, ip_address, ip_hash, path, bot_name,
            visitor_classification, risk_score, classification_reason, user_agent,
            isp, details
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            now,
            event.get("session_id"),
            event.get("ip_address") or "0.0.0.0",
            ip_hash,
            event.get("path") or "/",
            intelligence.get("bot_name"),
            intelligence["visitor_classification"],
            intelligence["risk_score"],
            intelligence.get("classification_reason"),
            event.get("user_agent"),
            location.get("isp"),
            json.dumps(
                {
                    "browser": event.get("browser"),
                    "device_type": event.get("device_type"),
                    "country": location.get("country"),
                    "city": location.get("city"),
                },
                ensure_ascii=True,
            ),
        ),
    )


def _event_intelligence(cursor: Any, session_id: str | None, ip_hash: str, event: dict[str, Any]) -> dict[str, Any]:
    if session_id:
        cursor.execute(
            """
            SELECT visitor_classification, is_bot, bot_name, risk_score, classification_reason, isp
            FROM visitor_sessions
            WHERE session_id = %s
            LIMIT 1
            """,
            (session_id,),
        )
        row = cursor.fetchone()
        if row:
            return {
                "visitor_classification": row[0] or "human",
                "is_bot": bool(row[1]),
                "bot_name": row[2],
                "risk_score": int(row[3] or 0),
                "classification_reason": row[4],
                "isp": row[5],
            }

    cursor.execute(
        """
        SELECT visitor_classification, is_bot, bot_name, risk_score, classification_reason, isp
        FROM visitor_events
        WHERE ip_hash = %s
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (ip_hash,),
    )
    row = cursor.fetchone()
    if row:
        return {
            "visitor_classification": row[0] or "human",
            "is_bot": bool(row[1]),
            "bot_name": row[2],
            "risk_score": int(row[3] or 0),
            "classification_reason": row[4],
            "isp": row[5],
        }

    fallback = classify_visit(event.get("user_agent"), event.get("browser"), event.get("device_type"), None, 0)
    return {**fallback, "isp": None}


def record_visit(event: dict[str, Any]) -> None:
    ip_address = event.get("ip_address") or "0.0.0.0"
    try:
        location = lookup_ip_location(ip_address)
    except Exception:
        # Core visit tracking should not depend on a third-party geo lookup.
        location = _empty_location()
    path = event.get("path") or "/"
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    ip_hash = _hash_ip(ip_address)

    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            recent_ip_requests = _recent_ip_request_count(cursor, ip_hash, now)
            intelligence = classify_visit(
                event.get("user_agent"),
                event.get("browser"),
                event.get("device_type"),
                location.get("isp"),
                recent_ip_requests,
            )
            cursor.execute(
                """
                INSERT INTO visitor_events (
                    visit_uuid, session_id, created_at, ip_address, ip_hash, path, page_title,
                    endpoint, method, status_code, referrer, user_agent, browser,
                    device_type, visitor_classification, is_bot, bot_name, risk_score,
                    classification_reason, country, region, city, timezone, isp, latitude,
                    longitude, time_spent_seconds, is_target_page
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(uuid.uuid4()),
                    event.get("session_id"),
                    now,
                    ip_address,
                    ip_hash,
                    path,
                    event.get("page_title") or TARGET_PAGE_LABELS.get(path, path),
                    event.get("endpoint"),
                    event.get("method") or "GET",
                    int(event.get("status_code") or 200),
                    event.get("referrer"),
                    event.get("user_agent"),
                    event.get("browser"),
                    event.get("device_type"),
                    intelligence["visitor_classification"],
                    intelligence["is_bot"],
                    intelligence.get("bot_name"),
                    intelligence["risk_score"],
                    intelligence.get("classification_reason"),
                    location.get("country"),
                    location.get("region"),
                    location.get("city"),
                    location.get("timezone"),
                    location.get("isp"),
                    location.get("latitude"),
                    location.get("longitude"),
                    event.get("time_spent_seconds"),
                    path in TARGET_PATHS,
                ),
            )
            _upsert_visitor_session(cursor, event.get("session_id"), event, ip_hash, now, location, intelligence)
            _log_bot_activity(cursor, event, ip_hash, now, location, intelligence)
        finally:
            cursor.close()


def record_click(event: dict[str, Any]) -> None:
    ip_address = event.get("ip_address") or "0.0.0.0"
    path = event.get("path") or "/"
    ip_hash = _hash_ip(ip_address)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            intelligence = _event_intelligence(cursor, event.get("session_id"), ip_hash, event)
            cursor.execute(
                """
                INSERT INTO click_events (
                    click_uuid, created_at, session_id, ip_address, ip_hash, path,
                    page_title, element_text, element_type, element_id, element_classes,
                    target_url, referrer, user_agent, browser, device_type,
                    visitor_classification, is_bot, bot_name, risk_score,
                    classification_reason, isp
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(uuid.uuid4()),
                    now,
                    event.get("session_id"),
                    ip_address,
                    ip_hash,
                    path,
                    event.get("page_title") or TARGET_PAGE_LABELS.get(path, path),
                    (event.get("element_text") or "")[:255],
                    (event.get("element_type") or "")[:80],
                    (event.get("element_id") or "")[:120],
                    (event.get("element_classes") or "")[:255],
                    event.get("target_url"),
                    event.get("referrer"),
                    event.get("user_agent"),
                    event.get("browser"),
                    event.get("device_type"),
                    intelligence["visitor_classification"],
                    intelligence["is_bot"],
                    intelligence.get("bot_name"),
                    intelligence["risk_score"],
                    intelligence.get("classification_reason"),
                    intelligence.get("isp"),
                ),
            )
        finally:
            cursor.close()


def record_engagement(event: dict[str, Any]) -> None:
    ip_address = event.get("ip_address") or "0.0.0.0"
    path = event.get("path") or "/"
    ip_hash = _hash_ip(ip_address)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    active_seconds = max(0, min(int(event.get("active_seconds") or 0), 24 * 60 * 60))
    max_scroll_percent = max(0, min(int(event.get("max_scroll_percent") or 0), 100))
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            intelligence = _event_intelligence(cursor, event.get("session_id"), ip_hash, event)
            cursor.execute(
                """
                INSERT INTO page_engagement_events (
                    engagement_uuid, created_at, session_id, ip_address, ip_hash, path,
                    page_title, active_seconds, max_scroll_percent, user_agent, browser, device_type,
                    visitor_classification, is_bot, bot_name, risk_score, classification_reason, isp
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()),
                    now,
                    event.get("session_id"),
                    ip_address,
                    ip_hash,
                    path,
                    event.get("page_title") or TARGET_PAGE_LABELS.get(path, path),
                    active_seconds,
                    max_scroll_percent,
                    event.get("user_agent"),
                    event.get("browser"),
                    event.get("device_type"),
                    intelligence["visitor_classification"],
                    intelligence["is_bot"],
                    intelligence.get("bot_name"),
                    intelligence["risk_score"],
                    intelligence.get("classification_reason"),
                    intelligence.get("isp"),
                ),
            )
        finally:
            cursor.close()


def record_conversion(event: dict[str, Any]) -> None:
    ip_address = event.get("ip_address") or "0.0.0.0"
    path = event.get("path") or "/"
    ip_hash = _hash_ip(ip_address)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            intelligence = _event_intelligence(cursor, event.get("session_id"), ip_hash, event)
            cursor.execute(
                """
                INSERT INTO conversion_events (
                    conversion_uuid, created_at, session_id, ip_address, ip_hash,
                    conversion_type, path, page_title, target, value_label, referrer,
                    user_agent, browser, device_type, visitor_classification, is_bot,
                    bot_name, risk_score, classification_reason, isp
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()),
                    now,
                    event.get("session_id"),
                    ip_address,
                    ip_hash,
                    (event.get("conversion_type") or "unknown")[:80],
                    path,
                    (event.get("page_title") or TARGET_PAGE_LABELS.get(path, path))[:255],
                    (event.get("target") or "")[:255],
                    (event.get("value_label") or "")[:255],
                    event.get("referrer"),
                    event.get("user_agent"),
                    event.get("browser"),
                    event.get("device_type"),
                    intelligence["visitor_classification"],
                    intelligence["is_bot"],
                    intelligence.get("bot_name"),
                    intelligence["risk_score"],
                    intelligence.get("classification_reason"),
                    intelligence.get("isp"),
                ),
            )
        finally:
            cursor.close()


def _fetch_all(cursor: Any, query: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
    cursor.execute(query, params)
    return list(cursor.fetchall())


def get_dashboard_data(days: int = 30) -> dict[str, Any]:
    days = max(1, min(days, 365))
    since = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=days)
    params = (since,)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT
                    COUNT(*) AS total_visits,
                    COUNT(DISTINCT ip_hash) AS unique_visitors,
                    SUM(is_target_page = 1) AS target_page_visits,
                    COUNT(DISTINCT CASE WHEN is_target_page = 1 THEN ip_hash END) AS target_unique_visitors
                FROM visitor_events
                WHERE created_at >= %s
                """,
                params,
            )
            overview = cursor.fetchone() or {}

            by_day = _fetch_all(
                cursor,
                """
                SELECT DATE(created_at) AS label, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY DATE(created_at)
                ORDER BY label
                """,
                params,
            )
            top_pages = _fetch_all(
                cursor,
                """
                SELECT page_title, path, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY page_title, path
                ORDER BY visits DESC
                LIMIT 10
                """,
                params,
            )
            target_pages = _fetch_all(
                cursor,
                """
                SELECT page_title, path, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                FROM visitor_events
                WHERE created_at >= %s
                    AND is_target_page = 1
                GROUP BY page_title, path
                ORDER BY visits DESC
                """,
                params,
            )
            browsers = _fetch_all(
                cursor,
                """
                SELECT COALESCE(browser, 'Unknown') AS label, COUNT(*) AS visits
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY COALESCE(browser, 'Unknown')
                ORDER BY visits DESC
                LIMIT 8
                """,
                params,
            )
            devices = _fetch_all(
                cursor,
                """
                SELECT COALESCE(device_type, 'Unknown') AS label, COUNT(*) AS visits
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY COALESCE(device_type, 'Unknown')
                ORDER BY visits DESC
                """,
                params,
            )
            locations = _fetch_all(
                cursor,
                """
                SELECT
                    COALESCE(NULLIF(city, ''), 'Unknown') AS city,
                    COALESCE(NULLIF(country, ''), 'Unknown') AS country,
                    COUNT(*) AS visits,
                    COUNT(DISTINCT ip_hash) AS visitors
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY COALESCE(NULLIF(city, ''), 'Unknown'), COALESCE(NULLIF(country, ''), 'Unknown')
                ORDER BY visits DESC
                LIMIT 10
                """,
                params,
            )
            referrers = _fetch_all(
                cursor,
                """
                SELECT COALESCE(NULLIF(referrer, ''), 'Direct') AS label, COUNT(*) AS visits
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY COALESCE(NULLIF(referrer, ''), 'Direct')
                ORDER BY visits DESC
                LIMIT 10
                """,
                params,
            )
            recent_visits = _fetch_all(
                cursor,
                """
                SELECT created_at, ip_address, path, page_title, city, country, browser, device_type, referrer
                FROM visitor_events
                ORDER BY created_at DESC
                LIMIT 25
                """,
                (),
            )
        finally:
            cursor.close()

    return {
        "ready": True,
        "error": None,
        "overview": {
            "total_visits": int(overview.get("total_visits") or 0),
            "unique_visitors": int(overview.get("unique_visitors") or 0),
            "target_page_visits": int(overview.get("target_page_visits") or 0),
            "target_unique_visitors": int(overview.get("target_unique_visitors") or 0),
        },
        "by_day": by_day,
        "top_pages": top_pages,
        "target_pages": target_pages,
        "browsers": browsers,
        "devices": devices,
        "locations": locations,
        "referrers": referrers,
        "recent_visits": recent_visits,
    }


def analytics_error_message(error: Exception) -> str:
    return f"Analytics database is not available: {error}"


def empty_dashboard_data(error: str | None = None) -> dict[str, Any]:
    return {
        "ready": False,
        "error": error,
        "overview": {
            "total_visits": 0,
            "unique_visitors": 0,
            "target_page_visits": 0,
            "target_unique_visitors": 0,
        },
        "by_day": [],
        "top_pages": [],
        "target_pages": [],
        "browsers": [],
        "devices": [],
        "locations": [],
        "referrers": [],
        "recent_visits": [],
    }
