from __future__ import annotations

import hashlib
import ipaddress
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


def _env_bool(name: str, default: str = "true") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _mysql_config(include_database: bool = True) -> dict[str, Any]:
    config: dict[str, Any] = {
        "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
        "port": int(os.getenv("MYSQL_PORT", "3306")),
        "user": os.getenv("MYSQL_USER", "root"),
        "password": os.getenv("MYSQL_PASSWORD", ""),
        "connection_timeout": int(os.getenv("MYSQL_CONNECTION_TIMEOUT", "3")),
        "autocommit": False,
    }
    if include_database:
        config["database"] = os.getenv("MYSQL_DATABASE", "amtelkom_analytics")
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
    database_name = os.getenv("MYSQL_DATABASE", "amtelkom_analytics")
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
                INDEX idx_target_created_at (is_target_page, created_at)
            ) ENGINE=InnoDB
            """
        )
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN session_id CHAR(36) NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN time_spent_seconds INT UNSIGNED NULL")
        _execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD INDEX idx_session_created_at (session_id, created_at)")
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
                INDEX idx_click_created_at (created_at),
                INDEX idx_click_path_created_at (path, created_at),
                INDEX idx_click_ip_created_at (ip_hash, created_at),
                INDEX idx_click_session_created_at (session_id, created_at),
                INDEX idx_click_element_text (element_text, created_at)
            ) ENGINE=InnoDB
            """
        )
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
                INDEX idx_engagement_created_at (created_at),
                INDEX idx_engagement_path_created_at (path, created_at),
                INDEX idx_engagement_ip_created_at (ip_hash, created_at),
                INDEX idx_engagement_session_created_at (session_id, created_at)
            ) ENGINE=InnoDB
            """
        )
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
                INDEX idx_conversion_created_at (created_at),
                INDEX idx_conversion_type_created_at (conversion_type, created_at),
                INDEX idx_conversion_ip_created_at (ip_hash, created_at),
                INDEX idx_conversion_session_created_at (session_id, created_at)
            ) ENGINE=InnoDB
            """
        )
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
    empty = {
        "country": None,
        "region": None,
        "city": None,
        "timezone": None,
        "isp": None,
        "latitude": None,
        "longitude": None,
    }
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


def record_visit(event: dict[str, Any]) -> None:
    ip_address = event.get("ip_address") or "0.0.0.0"
    location = lookup_ip_location(ip_address)
    path = event.get("path") or "/"

    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO visitor_events (
                    visit_uuid, session_id, created_at, ip_address, ip_hash, path, page_title,
                    endpoint, method, status_code, referrer, user_agent, browser,
                    device_type, country, region, city, timezone, isp, latitude,
                    longitude, time_spent_seconds, is_target_page
                )
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(uuid.uuid4()),
                    event.get("session_id"),
                    datetime.now(timezone.utc).replace(tzinfo=None),
                    ip_address,
                    _hash_ip(ip_address),
                    path,
                    event.get("page_title") or TARGET_PAGE_LABELS.get(path, path),
                    event.get("endpoint"),
                    event.get("method") or "GET",
                    int(event.get("status_code") or 200),
                    event.get("referrer"),
                    event.get("user_agent"),
                    event.get("browser"),
                    event.get("device_type"),
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
        finally:
            cursor.close()


def record_click(event: dict[str, Any]) -> None:
    ip_address = event.get("ip_address") or "0.0.0.0"
    path = event.get("path") or "/"
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO click_events (
                    click_uuid, created_at, session_id, ip_address, ip_hash, path,
                    page_title, element_text, element_type, element_id, element_classes,
                    target_url, referrer, user_agent, browser, device_type
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()),
                    datetime.now(timezone.utc).replace(tzinfo=None),
                    event.get("session_id"),
                    ip_address,
                    _hash_ip(ip_address),
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
                ),
            )
        finally:
            cursor.close()


def record_engagement(event: dict[str, Any]) -> None:
    ip_address = event.get("ip_address") or "0.0.0.0"
    path = event.get("path") or "/"
    active_seconds = max(0, min(int(event.get("active_seconds") or 0), 24 * 60 * 60))
    max_scroll_percent = max(0, min(int(event.get("max_scroll_percent") or 0), 100))
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO page_engagement_events (
                    engagement_uuid, created_at, session_id, ip_address, ip_hash, path,
                    page_title, active_seconds, max_scroll_percent, user_agent, browser, device_type
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()),
                    datetime.now(timezone.utc).replace(tzinfo=None),
                    event.get("session_id"),
                    ip_address,
                    _hash_ip(ip_address),
                    path,
                    event.get("page_title") or TARGET_PAGE_LABELS.get(path, path),
                    active_seconds,
                    max_scroll_percent,
                    event.get("user_agent"),
                    event.get("browser"),
                    event.get("device_type"),
                ),
            )
        finally:
            cursor.close()


def record_conversion(event: dict[str, Any]) -> None:
    ip_address = event.get("ip_address") or "0.0.0.0"
    path = event.get("path") or "/"
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO conversion_events (
                    conversion_uuid, created_at, session_id, ip_address, ip_hash,
                    conversion_type, path, page_title, target, value_label, referrer,
                    user_agent, browser, device_type
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(uuid.uuid4()),
                    datetime.now(timezone.utc).replace(tzinfo=None),
                    event.get("session_id"),
                    ip_address,
                    _hash_ip(ip_address),
                    (event.get("conversion_type") or "unknown")[:80],
                    path,
                    (event.get("page_title") or TARGET_PAGE_LABELS.get(path, path))[:255],
                    (event.get("target") or "")[:255],
                    (event.get("value_label") or "")[:255],
                    event.get("referrer"),
                    event.get("user_agent"),
                    event.get("browser"),
                    event.get("device_type"),
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
