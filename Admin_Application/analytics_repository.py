from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Literal

import mysql.connector


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

CAREERS_PATHS = ("/careers", "/career.html")
JOB_PATHS = ("/job-oss-bss-engineer.html", "/jobs/oss-bss-engineer")
SESSION_IDLE_MINUTES = 30


def mysql_config(include_database: bool = True) -> dict[str, Any]:
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


def execute_optional_schema_change(cursor: Any, statement: str) -> None:
    try:
        cursor.execute(statement)
    except mysql.connector.Error as exc:
        if exc.errno not in {1060, 1061}:  # duplicate column or duplicate key name
            raise


@contextmanager
def mysql_connection() -> Iterator[mysql.connector.MySQLConnection]:
    connection = mysql.connector.connect(**mysql_config())
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_database() -> None:
    database_name = os.getenv("MYSQL_DATABASE", "amtelkom_analytics")
    connection = mysql.connector.connect(**mysql_config(include_database=False))
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
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN session_id CHAR(36) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN time_spent_seconds INT UNSIGNED NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD INDEX idx_session_created_at (session_id, created_at)")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_activity_logs (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                created_at DATETIME(6) NOT NULL,
                admin_username VARCHAR(120),
                action VARCHAR(120) NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                details JSON NULL,
                INDEX idx_admin_activity_created_at (created_at),
                INDEX idx_admin_activity_action (action, created_at)
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
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_sessions (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                session_id CHAR(36) NOT NULL,
                admin_username VARCHAR(120) NOT NULL,
                ip_address VARCHAR(45),
                user_agent TEXT,
                created_at DATETIME(6) NOT NULL,
                last_seen_at DATETIME(6) NOT NULL,
                revoked_at DATETIME(6) NULL,
                UNIQUE KEY uniq_admin_session_id (session_id),
                INDEX idx_admin_sessions_user (admin_username, last_seen_at)
            ) ENGINE=InnoDB
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS request_logs (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                created_at DATETIME(6) NOT NULL,
                method VARCHAR(16) NOT NULL,
                path VARCHAR(255) NOT NULL,
                status_code SMALLINT UNSIGNED NOT NULL,
                duration_ms INT UNSIGNED,
                ip_address VARCHAR(45),
                user_agent TEXT,
                admin_username VARCHAR(120),
                INDEX idx_request_logs_created_at (created_at),
                INDEX idx_request_logs_path (path, created_at),
                INDEX idx_request_logs_status (status_code, created_at)
            ) ENGINE=InnoDB
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS error_logs (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                created_at DATETIME(6) NOT NULL,
                level VARCHAR(20) NOT NULL,
                message TEXT NOT NULL,
                path VARCHAR(255),
                traceback TEXT,
                INDEX idx_error_logs_created_at (created_at),
                INDEX idx_error_logs_level (level, created_at)
            ) ENGINE=InnoDB
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS suspicious_activity_logs (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                created_at DATETIME(6) NOT NULL,
                ip_address VARCHAR(45),
                event_type VARCHAR(120) NOT NULL,
                severity VARCHAR(20) NOT NULL,
                details JSON NULL,
                INDEX idx_suspicious_created_at (created_at),
                INDEX idx_suspicious_ip (ip_address, created_at)
            ) ENGINE=InnoDB
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS analytics_aggregates (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                period_type ENUM('daily', 'weekly', 'monthly') NOT NULL,
                period_start DATE NOT NULL,
                visitors INT UNSIGNED NOT NULL DEFAULT 0,
                unique_visitors INT UNSIGNED NOT NULL DEFAULT 0,
                page_views INT UNSIGNED NOT NULL DEFAULT 0,
                conversions INT UNSIGNED NOT NULL DEFAULT 0,
                bounce_rate DECIMAL(5,2) NOT NULL DEFAULT 0,
                created_at DATETIME(6) NOT NULL,
                updated_at DATETIME(6) NOT NULL,
                UNIQUE KEY uniq_analytics_period (period_type, period_start)
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


def utc_since(days: int) -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(days=max(1, min(days, 365)))


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def build_visit_filters(days: int, path: str = "", query: str = "") -> tuple[str, list[Any]]:
    clauses = ["created_at >= %s"]
    values: list[Any] = [utc_since(days)]
    if path:
        clauses.append("path = %s")
        values.append(path)
    if query:
        like = f"%{query}%"
        clauses.append(
            "("
            "ip_address LIKE %s OR path LIKE %s OR page_title LIKE %s OR "
            "city LIKE %s OR country LIKE %s OR browser LIKE %s OR referrer LIKE %s"
            ")"
        )
        values.extend([like, like, like, like, like, like, like])
    return " AND ".join(clauses), values


def fetch_all(cursor: Any, query: str, values: list[Any] | tuple[Any, ...]) -> list[dict[str, Any]]:
    cursor.execute(query, values)
    return list(cursor.fetchall())


def _fetch_one(cursor: Any, query: str, values: list[Any] | tuple[Any, ...]) -> dict[str, Any]:
    cursor.execute(query, values)
    return cursor.fetchone() or {}


def _scalar(cursor: Any, query: str, values: list[Any] | tuple[Any, ...] = ()) -> int:
    cursor.execute(query, values)
    row = cursor.fetchone()
    if isinstance(row, dict):
        return int(next(iter(row.values())) or 0)
    return int((row[0] if row else 0) or 0)


def _ratio(part: int | float, whole: int | float) -> float:
    return round((float(part) / float(whole) * 100), 2) if whole else 0.0


def _direct_or_domain_expression() -> str:
    return """
        CASE
            WHEN referrer IS NULL OR referrer = '' THEN 'Direct'
            WHEN referrer LIKE '%google.%' THEN 'Google'
            WHEN referrer LIKE '%bing.%' THEN 'Bing'
            WHEN referrer LIKE '%linkedin.%' THEN 'LinkedIn'
            WHEN referrer LIKE '%facebook.%' THEN 'Facebook'
            WHEN referrer LIKE '%instagram.%' THEN 'Instagram'
            ELSE referrer
        END
    """


def dashboard_data(days: int = 30) -> dict[str, Any]:
    days = max(1, min(days, 365))
    since = utc_since(days)
    today = utc_now().date()
    month_start = today.replace(day=1)
    active_since = utc_now() - timedelta(minutes=15)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            overview = _fetch_one(
                cursor,
                """
                SELECT
                    COUNT(*) AS total_visits,
                    COUNT(DISTINCT ip_hash) AS unique_visitors,
                    COUNT(DISTINCT path) AS pages_seen,
                    SUM(is_target_page = 1) AS target_page_visits,
                    COUNT(DISTINCT CASE WHEN is_target_page = 1 THEN ip_hash END) AS target_unique_visitors,
                    COUNT(DISTINCT CASE WHEN path IN (%s, %s) THEN ip_hash END) AS careers_visitors,
                    COUNT(CASE WHEN path IN (%s, %s) THEN 1 END) AS job_application_views
                FROM visitor_events
                WHERE created_at >= %s
                """,
                (*CAREERS_PATHS, *JOB_PATHS, since),
            )
            daily_visitors = _scalar(
                cursor,
                "SELECT COUNT(*) FROM visitor_events WHERE DATE(created_at) = %s",
                (today,),
            )
            monthly_visitors = _scalar(
                cursor,
                "SELECT COUNT(*) FROM visitor_events WHERE DATE(created_at) >= %s",
                (month_start,),
            )
            active_users = _scalar(
                cursor,
                "SELECT COUNT(DISTINCT ip_hash) FROM visitor_events WHERE created_at >= %s",
                (active_since,),
            )
            returning_visitors = _scalar(
                cursor,
                """
                SELECT COUNT(*) FROM (
                    SELECT ip_hash
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY ip_hash
                    HAVING COUNT(*) > 1
                ) returning_ips
                """,
                (since,),
            )
            bounced_visitors = _scalar(
                cursor,
                """
                SELECT COUNT(*) FROM (
                    SELECT ip_hash
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY ip_hash
                    HAVING COUNT(*) = 1
                ) bounced_ips
                """,
                (since,),
            )
            time_spent = _fetch_one(
                cursor,
                """
                SELECT AVG(seconds_spent) AS average_seconds
                FROM (
                    SELECT TIMESTAMPDIFF(
                               SECOND,
                               created_at,
                               LEAD(created_at) OVER (PARTITION BY COALESCE(session_id, ip_hash) ORDER BY created_at)
                           ) AS seconds_spent
                    FROM visitor_events
                    WHERE created_at >= %s
                ) ranked
                WHERE seconds_spent BETWEEN 1 AND 1800
                """,
                (since,),
            )
            click_overview = _fetch_one(
                cursor,
                """
                SELECT COUNT(*) AS total_clicks,
                       COUNT(DISTINCT ip_hash) AS unique_clickers,
                       COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS clicking_sessions
                FROM click_events
                WHERE created_at >= %s
                """,
                (since,),
            )
            conversion_overview = _fetch_one(
                cursor,
                """
                SELECT COUNT(*) AS total_conversions,
                       COUNT(DISTINCT ip_hash) AS converting_visitors,
                       COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS converting_sessions
                FROM conversion_events
                WHERE created_at >= %s
                """,
                (since,),
            )
            engagement_overview = _fetch_one(
                cursor,
                """
                SELECT AVG(active_seconds) AS average_active_seconds,
                       AVG(max_scroll_percent) AS average_scroll_percent
                FROM page_engagement_events
                WHERE created_at >= %s
                """,
                (since,),
            )
            unique_visitors = int(overview.get("unique_visitors") or 0)
            total_visits = int(overview.get("total_visits") or 0)
            job_views = int(overview.get("job_application_views") or 0)
            return {
                "overview": {
                    "total_visits": total_visits,
                    "active_users": active_users,
                    "daily_visitors": daily_visitors,
                    "monthly_visitors": monthly_visitors,
                    "returning_visitors": returning_visitors,
                    "bounce_rate": _ratio(bounced_visitors, unique_visitors),
                    "conversion_rate": _ratio(job_views, unique_visitors),
                    "average_time_spent_seconds": int(time_spent.get("average_seconds") or 0),
                    "total_clicks": int(click_overview.get("total_clicks") or 0),
                    "unique_clickers": int(click_overview.get("unique_clickers") or 0),
                    "clicking_sessions": int(click_overview.get("clicking_sessions") or 0),
                    "total_conversions": int(conversion_overview.get("total_conversions") or 0),
                    "converting_visitors": int(conversion_overview.get("converting_visitors") or 0),
                    "converting_sessions": int(conversion_overview.get("converting_sessions") or 0),
                    "average_active_seconds": int(engagement_overview.get("average_active_seconds") or 0),
                    "average_scroll_percent": int(engagement_overview.get("average_scroll_percent") or 0),
                    "unique_visitors": unique_visitors,
                    "pages_seen": int(overview.get("pages_seen") or 0),
                    "target_page_visits": int(overview.get("target_page_visits") or 0),
                    "target_unique_visitors": int(overview.get("target_unique_visitors") or 0),
                    "careers_visitors": int(overview.get("careers_visitors") or 0),
                    "job_application_views": job_views,
                },
                "daily": fetch_all(
                    cursor,
                    """
                    SELECT DATE(created_at) AS label, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY DATE(created_at)
                    ORDER BY label
                    """,
                    (since,),
                ),
                "hourly": fetch_all(
                    cursor,
                    """
                    SELECT HOUR(created_at) AS label, COUNT(*) AS visits
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY HOUR(created_at)
                    ORDER BY label
                    """,
                    (since,),
                ),
                "target_pages": fetch_all(
                    cursor,
                    """
                    SELECT page_title, path, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s AND is_target_page = 1
                    GROUP BY page_title, path
                    ORDER BY visits DESC
                    """,
                    (since,),
                ),
                "top_clicks": top_clicks(days, 10),
                "top_conversions": conversion_summary(days, 10),
                "top_engagement": engagement_summary(days, 10),
                "entry_pages": fetch_all(
                    cursor,
                    """
                    SELECT path, page_title, COUNT(*) AS visits
                    FROM (
                        SELECT path, page_title, ip_hash, created_at,
                               ROW_NUMBER() OVER (PARTITION BY ip_hash ORDER BY created_at ASC) AS row_num
                        FROM visitor_events
                        WHERE created_at >= %s
                    ) ranked
                    WHERE row_num = 1
                    GROUP BY path, page_title
                    ORDER BY visits DESC
                    LIMIT 10
                    """,
                    (since,),
                ),
                "exit_pages": fetch_all(
                    cursor,
                    """
                    SELECT path, page_title, COUNT(*) AS visits
                    FROM (
                        SELECT path, page_title, ip_hash, created_at,
                               ROW_NUMBER() OVER (PARTITION BY ip_hash ORDER BY created_at DESC) AS row_num
                        FROM visitor_events
                        WHERE created_at >= %s
                    ) ranked
                    WHERE row_num = 1
                    GROUP BY path, page_title
                    ORDER BY visits DESC
                    LIMIT 10
                    """,
                    (since,),
                ),
                "top_pages": fetch_all(
                    cursor,
                    """
                    SELECT page_title, path, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY page_title, path
                    ORDER BY visits DESC
                    LIMIT 12
                    """,
                    (since,),
                ),
                "countries": fetch_all(
                    cursor,
                    """
                    SELECT COALESCE(NULLIF(country, ''), 'Unknown') AS label,
                           COUNT(*) AS visits,
                           COUNT(DISTINCT ip_hash) AS visitors,
                           MAX(latitude) AS latitude,
                           MAX(longitude) AS longitude
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY COALESCE(NULLIF(country, ''), 'Unknown')
                    ORDER BY visits DESC
                    LIMIT 20
                    """,
                    (since,),
                ),
                "locations": fetch_all(
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
                    LIMIT 12
                    """,
                    (since,),
                ),
                "devices": fetch_all(
                    cursor,
                    """
                    SELECT COALESCE(device_type, 'Unknown') AS label, COUNT(*) AS visits
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY COALESCE(device_type, 'Unknown')
                    ORDER BY visits DESC
                    """,
                    (since,),
                ),
                "browsers": fetch_all(
                    cursor,
                    """
                    SELECT COALESCE(browser, 'Unknown') AS label, COUNT(*) AS visits
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY COALESCE(browser, 'Unknown')
                    ORDER BY visits DESC
                    LIMIT 8
                    """,
                    (since,),
                ),
                "referrers": fetch_all(
                    cursor,
                    """
                    SELECT
                        CASE
                            WHEN referrer IS NULL OR referrer = '' THEN 'Direct'
                            WHEN referrer LIKE '%google.%' THEN 'Google'
                            WHEN referrer LIKE '%bing.%' THEN 'Bing'
                            WHEN referrer LIKE '%linkedin.%' THEN 'LinkedIn'
                            WHEN referrer LIKE '%facebook.%' THEN 'Facebook'
                            WHEN referrer LIKE '%instagram.%' THEN 'Instagram'
                            ELSE referrer
                        END AS label,
                        COUNT(*) AS visits,
                        COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY label
                    ORDER BY visits DESC
                    LIMIT 10
                    """,
                    (since,),
                ),
                "reports": report_data(days),
                "live": realtime_data(),
                "recent_visits": fetch_visits(days=days, limit=15),
            }
        finally:
            cursor.close()


def analytics_breakdown(kind: str, days: int = 30) -> dict[str, Any]:
    days = max(1, min(days, 365))
    since = utc_since(days)
    configs = {
        "pages": {
            "title": "Page Analytics",
            "subtitle": "Top visited pages, unique visitors, entry volume, and exit volume.",
            "query": """
                SELECT page_title AS label, path, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors,
                       SUM(is_target_page = 1) AS target_visits
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY page_title, path
                ORDER BY visits DESC
                LIMIT 50
            """,
        },
        "careers": {
            "title": "Careers Page Analytics",
            "subtitle": "Traffic and engagement for AMTEL careers pages.",
            "query": """
                SELECT page_title AS label, path, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors,
                       COUNT(DISTINCT country) AS countries
                FROM visitor_events
                WHERE created_at >= %s AND path IN ('/careers', '/career.html')
                GROUP BY page_title, path
                ORDER BY visits DESC
            """,
        },
        "jobs": {
            "title": "Job Application Analytics",
            "subtitle": "Views and conversion proxy for job pages.",
            "query": """
                SELECT page_title AS label, path, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors,
                       COUNT(DISTINCT referrer) AS sources
                FROM visitor_events
                WHERE created_at >= %s AND path IN ('/job-oss-bss-engineer.html', '/jobs/oss-bss-engineer')
                GROUP BY page_title, path
                ORDER BY visits DESC
            """,
        },
        "devices": {
            "title": "Device Analytics",
            "subtitle": "Desktop, mobile, tablet, and bot traffic.",
            "query": """
                SELECT COALESCE(device_type, 'Unknown') AS label, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY COALESCE(device_type, 'Unknown')
                ORDER BY visits DESC
            """,
        },
        "browsers": {
            "title": "Browser Analytics",
            "subtitle": "Browser distribution for compatibility monitoring.",
            "query": """
                SELECT COALESCE(browser, 'Unknown') AS label, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY COALESCE(browser, 'Unknown')
                ORDER BY visits DESC
            """,
        },
        "countries": {
            "title": "Country Analytics",
            "subtitle": "Country-level visitor distribution.",
            "query": """
                SELECT COALESCE(NULLIF(country, ''), 'Unknown') AS label, COUNT(*) AS visits,
                       COUNT(DISTINCT ip_hash) AS visitors, MAX(latitude) AS latitude, MAX(longitude) AS longitude
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY COALESCE(NULLIF(country, ''), 'Unknown')
                ORDER BY visits DESC
            """,
        },
        "sources": {
            "title": "Traffic Source Analytics",
            "subtitle": "Referral source performance and direct traffic.",
            "query": """
                SELECT
                    CASE
                        WHEN referrer IS NULL OR referrer = '' THEN 'Direct'
                        WHEN referrer LIKE '%google.%' THEN 'Google'
                        WHEN referrer LIKE '%bing.%' THEN 'Bing'
                        WHEN referrer LIKE '%linkedin.%' THEN 'LinkedIn'
                        WHEN referrer LIKE '%facebook.%' THEN 'Facebook'
                        WHEN referrer LIKE '%instagram.%' THEN 'Instagram'
                        ELSE referrer
                    END AS label,
                    COUNT(*) AS visits,
                    COUNT(DISTINCT ip_hash) AS visitors
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY label
                ORDER BY visits DESC
            """,
        },
    }
    if kind not in configs:
        raise ValueError("Unknown analytics breakdown.")
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            rows = fetch_all(cursor, configs[kind]["query"], (since,))
            return {**configs[kind], "rows": rows, "days": days, "kind": kind}
        finally:
            cursor.close()


def report_data(days: int = 30) -> dict[str, list[dict[str, Any]]]:
    since = utc_since(days)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return {
                "daily": fetch_all(
                    cursor,
                    """
                    SELECT DATE(created_at) AS period, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY DATE(created_at)
                    ORDER BY period DESC
                    LIMIT 31
                    """,
                    (since,),
                ),
                "weekly": fetch_all(
                    cursor,
                    """
                    SELECT YEARWEEK(created_at, 1) AS period, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY YEARWEEK(created_at, 1)
                    ORDER BY period DESC
                    LIMIT 12
                    """,
                    (since,),
                ),
                "monthly": fetch_all(
                    cursor,
                    """
                    SELECT DATE_FORMAT(created_at, '%Y-%m') AS period, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY DATE_FORMAT(created_at, '%Y-%m')
                    ORDER BY period DESC
                    LIMIT 12
                    """,
                    (since,),
                ),
            }
        finally:
            cursor.close()


def realtime_data() -> dict[str, Any]:
    active_since = utc_now() - timedelta(minutes=15)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return {
                "active_visitors": _scalar(
                    cursor,
                    "SELECT COUNT(DISTINCT ip_hash) FROM visitor_events WHERE created_at >= %s",
                    (active_since,),
                ),
                "live_page_views": _scalar(
                    cursor,
                    "SELECT COUNT(*) FROM visitor_events WHERE created_at >= %s",
                    (active_since,),
                ),
                "active_sessions": _scalar(
                    cursor,
                    "SELECT COUNT(DISTINCT COALESCE(session_id, ip_hash)) FROM visitor_events WHERE created_at >= %s",
                    (active_since,),
                ),
                "current_locations": fetch_all(
                    cursor,
                    """
                    SELECT COALESCE(NULLIF(city, ''), 'Unknown') AS city,
                           COALESCE(NULLIF(country, ''), 'Unknown') AS country,
                           COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY COALESCE(NULLIF(city, ''), 'Unknown'), COALESCE(NULLIF(country, ''), 'Unknown')
                    ORDER BY visitors DESC
                    LIMIT 20
                    """,
                    (active_since,),
                ),
                "recent_page_views": fetch_visits(days=1, limit=25),
            }
        finally:
            cursor.close()


def top_clicks(days: int = 30, limit: int = 25) -> list[dict[str, Any]]:
    since = utc_since(days)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                """
                SELECT COALESCE(NULLIF(element_text, ''), target_url, 'Unlabeled click') AS label,
                       path,
                       target_url,
                       COUNT(*) AS clicks,
                       COUNT(DISTINCT ip_hash) AS visitors,
                       COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS sessions
                FROM click_events
                WHERE created_at >= %s
                GROUP BY COALESCE(NULLIF(element_text, ''), target_url, 'Unlabeled click'), path, target_url
                ORDER BY clicks DESC
                LIMIT %s
                """,
                (since, max(1, min(limit, 100))),
            )
        finally:
            cursor.close()


def fetch_clicks(days: int = 30, query: str = "", limit: int = 500) -> list[dict[str, Any]]:
    clauses = ["created_at >= %s"]
    values: list[Any] = [utc_since(days)]
    if query:
        like = f"%{query}%"
        clauses.append(
            "(ip_address LIKE %s OR path LIKE %s OR element_text LIKE %s OR target_url LIKE %s OR browser LIKE %s)"
        )
        values.extend([like, like, like, like, like])
    values.append(max(1, min(limit, 1000)))
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                f"""
                SELECT id, created_at, session_id, ip_address, path, page_title,
                       element_text, element_type, element_id, element_classes,
                       target_url, referrer, user_agent, browser, device_type
                FROM click_events
                WHERE {" AND ".join(clauses)}
                ORDER BY created_at DESC
                LIMIT %s
                """,
                values,
            )
        finally:
            cursor.close()


def conversion_summary(days: int = 30, limit: int = 25) -> list[dict[str, Any]]:
    since = utc_since(days)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                """
                SELECT conversion_type,
                       COALESCE(NULLIF(value_label, ''), target, conversion_type) AS label,
                       path,
                       COUNT(*) AS conversions,
                       COUNT(DISTINCT ip_hash) AS visitors,
                       COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS sessions
                FROM conversion_events
                WHERE created_at >= %s
                GROUP BY conversion_type, COALESCE(NULLIF(value_label, ''), target, conversion_type), path
                ORDER BY conversions DESC
                LIMIT %s
                """,
                (since, max(1, min(limit, 100))),
            )
        finally:
            cursor.close()


def fetch_conversions(days: int = 30, query: str = "", limit: int = 500) -> list[dict[str, Any]]:
    clauses = ["created_at >= %s"]
    values: list[Any] = [utc_since(days)]
    if query:
        like = f"%{query}%"
        clauses.append(
            "(ip_address LIKE %s OR conversion_type LIKE %s OR path LIKE %s OR target LIKE %s OR value_label LIKE %s)"
        )
        values.extend([like, like, like, like, like])
    values.append(max(1, min(limit, 1000)))
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                f"""
                SELECT id, created_at, session_id, ip_address, conversion_type, path,
                       page_title, target, value_label, referrer, browser, device_type
                FROM conversion_events
                WHERE {" AND ".join(clauses)}
                ORDER BY created_at DESC
                LIMIT %s
                """,
                values,
            )
        finally:
            cursor.close()


def engagement_summary(days: int = 30, limit: int = 25) -> list[dict[str, Any]]:
    since = utc_since(days)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                """
                SELECT path,
                       COALESCE(NULLIF(page_title, ''), path) AS label,
                       COUNT(*) AS samples,
                       COUNT(DISTINCT ip_hash) AS visitors,
                       AVG(active_seconds) AS average_active_seconds,
                       AVG(max_scroll_percent) AS average_scroll_percent
                FROM page_engagement_events
                WHERE created_at >= %s
                GROUP BY path, COALESCE(NULLIF(page_title, ''), path)
                ORDER BY average_active_seconds DESC
                LIMIT %s
                """,
                (since, max(1, min(limit, 100))),
            )
        finally:
            cursor.close()


def fetch_engagement(days: int = 30, query: str = "", limit: int = 500) -> list[dict[str, Any]]:
    clauses = ["created_at >= %s"]
    values: list[Any] = [utc_since(days)]
    if query:
        like = f"%{query}%"
        clauses.append("(ip_address LIKE %s OR path LIKE %s OR page_title LIKE %s OR browser LIKE %s)")
        values.extend([like, like, like, like])
    values.append(max(1, min(limit, 1000)))
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                f"""
                SELECT id, created_at, session_id, ip_address, path, page_title,
                       active_seconds, max_scroll_percent, browser, device_type
                FROM page_engagement_events
                WHERE {" AND ".join(clauses)}
                ORDER BY created_at DESC
                LIMIT %s
                """,
                values,
            )
        finally:
            cursor.close()


def visitor_ip_summary(days: int = 365, query: str = "", limit: int = 1000) -> list[dict[str, Any]]:
    clauses = ["created_at >= %s"]
    values: list[Any] = [utc_since(days)]
    if query:
        like = f"%{query}%"
        clauses.append(
            "(ip_address LIKE %s OR city LIKE %s OR country LIKE %s OR browser LIKE %s OR device_type LIKE %s)"
        )
        values.extend([like, like, like, like, like])
    values.append(max(1, min(limit, 5000)))
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                f"""
                SELECT ip_address,
                       COUNT(*) AS visits,
                       COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS sessions,
                       MIN(created_at) AS first_seen_at,
                       MAX(created_at) AS last_seen_at,
                       COALESCE(NULLIF(city, ''), 'Unknown') AS city,
                       COALESCE(NULLIF(country, ''), 'Unknown') AS country,
                       COALESCE(NULLIF(browser, ''), 'Unknown') AS browser,
                       COALESCE(NULLIF(device_type, ''), 'Unknown') AS device_type,
                       MAX(isp) AS isp
                FROM visitor_events
                WHERE {" AND ".join(clauses)}
                GROUP BY ip_address,
                         COALESCE(NULLIF(city, ''), 'Unknown'),
                         COALESCE(NULLIF(country, ''), 'Unknown'),
                         COALESCE(NULLIF(browser, ''), 'Unknown'),
                         COALESCE(NULLIF(device_type, ''), 'Unknown')
                ORDER BY last_seen_at DESC
                LIMIT %s
                """,
                values,
            )
        finally:
            cursor.close()


def fetch_visits(days: int = 30, path: str = "", query: str = "", limit: int = 200) -> list[dict[str, Any]]:
    where_sql, values = build_visit_filters(days, path, query)
    values.append(max(1, min(limit, 1000)))
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                f"""
                SELECT
                    id, created_at, ip_address, path, page_title, status_code,
                    referrer, user_agent, browser, device_type, country, region,
                    city, timezone, isp, latitude, longitude, is_target_page,
                    session_id, time_spent_seconds
                FROM visitor_events
                WHERE {where_sql}
                ORDER BY created_at DESC
                LIMIT %s
                """,
                values,
            )
        finally:
            cursor.close()


def distinct_paths(days: int = 365) -> list[str]:
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                SELECT DISTINCT path
                FROM visitor_events
                WHERE created_at >= %s
                ORDER BY path
                """,
                (utc_since(days),),
            )
            return [row[0] for row in cursor.fetchall()]
        finally:
            cursor.close()


def fetch_logs(kind: Literal["requests", "errors", "suspicious", "admin"], limit: int = 200) -> list[dict[str, Any]]:
    table_queries = {
        "requests": """
            SELECT created_at, method, path, status_code, duration_ms, ip_address, admin_username, user_agent
            FROM request_logs
            ORDER BY created_at DESC
            LIMIT %s
        """,
        "errors": """
            SELECT created_at, level, message, path, traceback
            FROM error_logs
            ORDER BY created_at DESC
            LIMIT %s
        """,
        "suspicious": """
            SELECT created_at, ip_address, event_type, severity, details
            FROM suspicious_activity_logs
            ORDER BY created_at DESC
            LIMIT %s
        """,
        "admin": """
            SELECT created_at, admin_username, action, ip_address, details
            FROM admin_activity_logs
            ORDER BY created_at DESC
            LIMIT %s
        """,
    }
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(cursor, table_queries[kind], (max(1, min(limit, 1000)),))
        finally:
            cursor.close()


def log_admin_activity(action: str, admin_username: str | None, ip_address: str | None, user_agent: str | None, details: str | None = None) -> None:
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO admin_activity_logs (created_at, admin_username, action, ip_address, user_agent, details)
                VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (utc_now(), admin_username, action, ip_address, user_agent, details),
            )
        finally:
            cursor.close()


def upsert_admin_session(session_id: str, admin_username: str, ip_address: str | None, user_agent: str | None) -> None:
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            now = utc_now()
            cursor.execute(
                """
                INSERT INTO admin_sessions (session_id, admin_username, ip_address, user_agent, created_at, last_seen_at)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE last_seen_at = VALUES(last_seen_at), revoked_at = NULL
                """,
                (session_id, admin_username, ip_address, user_agent, now, now),
            )
        finally:
            cursor.close()


def admin_session_active(session_id: str) -> bool:
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute(
                """
                SELECT revoked_at
                FROM admin_sessions
                WHERE session_id = %s
                LIMIT 1
                """,
                (session_id,),
            )
            row = cursor.fetchone()
            return bool(row and row.get("revoked_at") is None)
        finally:
            cursor.close()


def touch_admin_session(session_id: str) -> None:
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                UPDATE admin_sessions
                SET last_seen_at = %s
                WHERE session_id = %s AND revoked_at IS NULL
                """,
                (utc_now(), session_id),
            )
        finally:
            cursor.close()


def revoke_admin_session(session_id: str) -> None:
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                "UPDATE admin_sessions SET revoked_at = %s WHERE session_id = %s",
                (utc_now(), session_id),
            )
        finally:
            cursor.close()


def log_request(method: str, path: str, status_code: int, duration_ms: int, ip_address: str | None, user_agent: str | None, admin_username: str | None) -> None:
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO request_logs (created_at, method, path, status_code, duration_ms, ip_address, user_agent, admin_username)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (utc_now(), method, path[:255], status_code, duration_ms, ip_address, user_agent, admin_username),
            )
        finally:
            cursor.close()


def log_error(level: str, message: str, path: str | None = None, traceback: str | None = None) -> None:
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO error_logs (created_at, level, message, path, traceback)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (utc_now(), level, message, path, traceback),
            )
        finally:
            cursor.close()


def log_suspicious_activity(ip_address: str | None, event_type: str, severity: str, details: str | None = None) -> None:
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO suspicious_activity_logs (created_at, ip_address, event_type, severity, details)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (utc_now(), ip_address, event_type, severity, details),
            )
        finally:
            cursor.close()


def refresh_analytics_aggregates(days: int = 90) -> int:
    since = utc_since(days)
    now = utc_now()
    with mysql_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO analytics_aggregates (
                    period_type, period_start, visitors, unique_visitors, page_views,
                    conversions, bounce_rate, created_at, updated_at
                )
                SELECT
                    'daily',
                    DATE(created_at),
                    COUNT(*),
                    COUNT(DISTINCT ip_hash),
                    COUNT(*),
                    SUM(path IN ('/job-oss-bss-engineer.html', '/jobs/oss-bss-engineer')),
                    0,
                    %s,
                    %s
                FROM visitor_events
                WHERE created_at >= %s
                GROUP BY DATE(created_at)
                ON DUPLICATE KEY UPDATE
                    visitors = VALUES(visitors),
                    unique_visitors = VALUES(unique_visitors),
                    page_views = VALUES(page_views),
                    conversions = VALUES(conversions),
                    updated_at = VALUES(updated_at)
                """,
                (now, now, since),
            )
            return cursor.rowcount
        finally:
            cursor.close()
