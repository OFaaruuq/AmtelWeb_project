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

LEGACY_CLASSIFICATION_SQL = """
    CASE
        WHEN LOWER(COALESCE(visitor_classification, '')) = 'bot'
            OR COALESCE(is_bot, 0) = 1
            OR LOWER(COALESCE(user_agent, '')) REGEXP 'bot|crawl|crawler|spider|slurp|semrush|amazonbot|bingpreview|headless'
            OR LOWER(COALESCE(browser, '')) = 'bot'
            OR LOWER(COALESCE(device_type, '')) = 'bot'
        THEN 'bot'
        WHEN LOWER(COALESCE(visitor_classification, '')) = 'suspicious'
            OR LOWER(COALESCE(isp, '')) REGEXP 'amazon|aws|microsoft|azure|google cloud|digitalocean|linode|akamai|ovh|hetzner|contabo|vultr|cloudflare|leaseweb|oracle|alibaba|tencent'
            OR COALESCE(risk_score, 0) >= 70
        THEN 'suspicious'
        ELSE 'human'
    END
"""


def traffic_mode(value: str | None) -> str:
    value = (value or "human").strip().lower()
    return value if value in {"human", "bot", "suspicious", "all"} else "human"


def traffic_condition(mode: str | None = "human", alias: str = "") -> str:
    selected = traffic_mode(mode)
    if selected == "all":
        return "1 = 1"
    prefix = f"{alias}." if alias else ""
    expression = LEGACY_CLASSIFICATION_SQL.replace("visitor_classification", f"{prefix}visitor_classification")
    expression = expression.replace("user_agent", f"{prefix}user_agent")
    expression = expression.replace("browser", f"{prefix}browser")
    expression = expression.replace("device_type", f"{prefix}device_type")
    expression = expression.replace("isp", f"{prefix}isp")
    expression = expression.replace("is_bot", f"{prefix}is_bot")
    expression = expression.replace("risk_score", f"{prefix}risk_score")
    if selected == "human":
        return f"({expression}) = 'human'"
    if selected == "bot":
        return f"({expression}) = 'bot'"
    return f"({expression}) = 'suspicious'"


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
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN session_id CHAR(36) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN time_spent_seconds INT UNSIGNED NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human'")
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN is_bot BOOLEAN NOT NULL DEFAULT FALSE")
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN bot_name VARCHAR(120) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0")
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD COLUMN classification_reason VARCHAR(255) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD INDEX idx_session_created_at (session_id, created_at)")
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD INDEX idx_class_created_at (visitor_classification, created_at)")
        execute_optional_schema_change(cursor, "ALTER TABLE visitor_events ADD INDEX idx_bot_created_at (is_bot, created_at)")
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
        execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human'")
        execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN is_bot BOOLEAN NOT NULL DEFAULT FALSE")
        execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN bot_name VARCHAR(120) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0")
        execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN classification_reason VARCHAR(255) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD COLUMN isp VARCHAR(255) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE click_events ADD INDEX idx_click_class_created (visitor_classification, created_at)")
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
        execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human'")
        execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN is_bot BOOLEAN NOT NULL DEFAULT FALSE")
        execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN bot_name VARCHAR(120) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0")
        execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN classification_reason VARCHAR(255) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD COLUMN isp VARCHAR(255) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE page_engagement_events ADD INDEX idx_engagement_class_created (visitor_classification, created_at)")
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
        execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN visitor_classification VARCHAR(20) NOT NULL DEFAULT 'human'")
        execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN is_bot BOOLEAN NOT NULL DEFAULT FALSE")
        execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN bot_name VARCHAR(120) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN risk_score TINYINT UNSIGNED NOT NULL DEFAULT 0")
        execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN classification_reason VARCHAR(255) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD COLUMN isp VARCHAR(255) NULL")
        execute_optional_schema_change(cursor, "ALTER TABLE conversion_events ADD INDEX idx_conversion_class_created (visitor_classification, created_at)")
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
                human_visits INT UNSIGNED NOT NULL DEFAULT 0,
                bot_visits INT UNSIGNED NOT NULL DEFAULT 0,
                suspicious_visits INT UNSIGNED NOT NULL DEFAULT 0,
                sessions INT UNSIGNED NOT NULL DEFAULT 0,
                average_session_seconds INT UNSIGNED NOT NULL DEFAULT 0,
                geo_stats JSON NULL,
                bounce_rate DECIMAL(5,2) NOT NULL DEFAULT 0,
                created_at DATETIME(6) NOT NULL,
                updated_at DATETIME(6) NOT NULL,
                UNIQUE KEY uniq_analytics_period (period_type, period_start)
            ) ENGINE=InnoDB
            """
        )
        execute_optional_schema_change(cursor, "ALTER TABLE analytics_aggregates ADD COLUMN human_visits INT UNSIGNED NOT NULL DEFAULT 0")
        execute_optional_schema_change(cursor, "ALTER TABLE analytics_aggregates ADD COLUMN bot_visits INT UNSIGNED NOT NULL DEFAULT 0")
        execute_optional_schema_change(cursor, "ALTER TABLE analytics_aggregates ADD COLUMN suspicious_visits INT UNSIGNED NOT NULL DEFAULT 0")
        execute_optional_schema_change(cursor, "ALTER TABLE analytics_aggregates ADD COLUMN sessions INT UNSIGNED NOT NULL DEFAULT 0")
        execute_optional_schema_change(cursor, "ALTER TABLE analytics_aggregates ADD COLUMN average_session_seconds INT UNSIGNED NOT NULL DEFAULT 0")
        execute_optional_schema_change(cursor, "ALTER TABLE analytics_aggregates ADD COLUMN geo_stats JSON NULL")
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


def build_visit_filters(days: int, path: str = "", query: str = "", mode: str = "human") -> tuple[str, list[Any]]:
    clauses = ["created_at >= %s", traffic_condition(mode)]
    values: list[Any] = [utc_since(days)]
    if path:
        clauses.append("path = %s")
        values.append(path)
    if query:
        like = f"%{query}%"
        clauses.append(
            "("
            "ip_address LIKE %s OR path LIKE %s OR page_title LIKE %s OR "
            "city LIKE %s OR country LIKE %s OR browser LIKE %s OR referrer LIKE %s OR "
            "visitor_classification LIKE %s OR bot_name LIKE %s OR classification_reason LIKE %s"
            ")"
        )
        values.extend([like, like, like, like, like, like, like, like, like, like])
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


def dashboard_data(days: int = 30, mode: str = "human") -> dict[str, Any]:
    days = max(1, min(days, 365))
    mode = traffic_mode(mode)
    visit_filter = traffic_condition(mode)
    since = utc_since(days)
    today = utc_now().date()
    month_start = today.replace(day=1)
    active_since = utc_now() - timedelta(minutes=15)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            overview = _fetch_one(
                cursor,
                f"""
                SELECT
                    COUNT(*) AS total_visits,
                    COUNT(DISTINCT ip_hash) AS unique_visitors,
                    COUNT(DISTINCT path) AS pages_seen,
                    SUM(is_target_page = 1) AS target_page_visits,
                    COUNT(DISTINCT CASE WHEN is_target_page = 1 THEN ip_hash END) AS target_unique_visitors,
                    COUNT(DISTINCT CASE WHEN path IN (%s, %s) THEN ip_hash END) AS careers_visitors,
                    COUNT(CASE WHEN path IN (%s, %s) THEN 1 END) AS job_application_views
                FROM visitor_events
                WHERE created_at >= %s AND {visit_filter}
                """,
                (*CAREERS_PATHS, *JOB_PATHS, since),
            )
            daily_visitors = _scalar(
                cursor,
                f"SELECT COUNT(*) FROM visitor_events WHERE DATE(created_at) = %s AND {visit_filter}",
                (today,),
            )
            monthly_visitors = _scalar(
                cursor,
                f"SELECT COUNT(*) FROM visitor_events WHERE DATE(created_at) >= %s AND {visit_filter}",
                (month_start,),
            )
            active_users = _scalar(
                cursor,
                f"SELECT COUNT(DISTINCT ip_hash) FROM visitor_events WHERE created_at >= %s AND {visit_filter}",
                (active_since,),
            )
            total_sessions = _scalar(
                cursor,
                f"""
                SELECT COUNT(*) FROM (
                    SELECT COALESCE(session_id, ip_hash) AS session_key
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY COALESCE(session_id, ip_hash)
                ) sessions
                """,
                (since,),
            )
            active_sessions = _scalar(
                cursor,
                f"""
                SELECT COUNT(DISTINCT COALESCE(session_id, ip_hash))
                FROM visitor_events
                WHERE created_at >= %s AND {visit_filter}
                """,
                (active_since,),
            )
            session_duration = _fetch_one(
                cursor,
                f"""
                SELECT AVG(duration_seconds) AS average_seconds
                FROM (
                    SELECT TIMESTAMPDIFF(SECOND, MIN(created_at), MAX(created_at)) AS duration_seconds
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY COALESCE(session_id, ip_hash)
                ) sessions
                WHERE duration_seconds BETWEEN 0 AND 1800
                """,
                (since,),
            )
            returning_visitors = _scalar(
                cursor,
                f"""
                SELECT COUNT(*) FROM (
                    SELECT ip_hash
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY ip_hash
                    HAVING COUNT(*) > 1
                ) returning_ips
                """,
                (since,),
            )
            bounced_visitors = _scalar(
                cursor,
                f"""
                SELECT COUNT(*) FROM (
                    SELECT COALESCE(session_id, ip_hash) AS session_key
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY COALESCE(session_id, ip_hash)
                    HAVING COUNT(*) = 1
                ) bounced_ips
                """,
                (since,),
            )
            time_spent = _fetch_one(
                cursor,
                f"""
                SELECT AVG(seconds_spent) AS average_seconds
                FROM (
                    SELECT TIMESTAMPDIFF(
                               SECOND,
                               created_at,
                               LEAD(created_at) OVER (PARTITION BY COALESCE(session_id, ip_hash) ORDER BY created_at)
                           ) AS seconds_spent
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                ) ranked
                WHERE seconds_spent BETWEEN 1 AND 1800
                """,
                (since,),
            )
            click_overview = _fetch_one(
                cursor,
                f"""
                SELECT COUNT(*) AS total_clicks,
                       COUNT(DISTINCT ip_hash) AS unique_clickers,
                       COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS clicking_sessions
                FROM click_events
                WHERE created_at >= %s AND {traffic_condition(mode)}
                """,
                (since,),
            )
            conversion_overview = _fetch_one(
                cursor,
                f"""
                SELECT COUNT(*) AS total_conversions,
                       COUNT(DISTINCT ip_hash) AS converting_visitors,
                       COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS converting_sessions
                FROM conversion_events
                WHERE created_at >= %s AND {traffic_condition(mode)}
                """,
                (since,),
            )
            engagement_overview = _fetch_one(
                cursor,
                f"""
                SELECT AVG(active_seconds) AS average_active_seconds,
                       AVG(max_scroll_percent) AS average_scroll_percent
                FROM page_engagement_events
                WHERE created_at >= %s AND {traffic_condition(mode)}
                """,
                (since,),
            )
            unique_visitors = int(overview.get("unique_visitors") or 0)
            total_visits = int(overview.get("total_visits") or 0)
            job_views = int(overview.get("job_application_views") or 0)
            traffic_mix = _fetch_one(
                cursor,
                f"""
                SELECT
                    SUM(({LEGACY_CLASSIFICATION_SQL}) = 'human') AS human_visits,
                    SUM(({LEGACY_CLASSIFICATION_SQL}) = 'bot') AS bot_visits,
                    SUM(({LEGACY_CLASSIFICATION_SQL}) = 'suspicious') AS suspicious_visits,
                    COUNT(*) AS all_visits
                FROM visitor_events
                WHERE created_at >= %s
                """,
                (since,),
            )
            return {
                "traffic_mode": mode,
                "overview": {
                    "total_visits": total_visits,
                    "active_users": active_users,
                    "total_sessions": total_sessions,
                    "active_sessions": active_sessions,
                    "average_session_duration_seconds": int(session_duration.get("average_seconds") or 0),
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
                    "human_visits": int(traffic_mix.get("human_visits") or 0),
                    "bot_visits": int(traffic_mix.get("bot_visits") or 0),
                    "suspicious_visits": int(traffic_mix.get("suspicious_visits") or 0),
                    "bot_percentage": _ratio(int(traffic_mix.get("bot_visits") or 0), int(traffic_mix.get("all_visits") or 0)),
                },
                "daily": fetch_all(
                    cursor,
                    f"""
                    SELECT DATE(created_at) AS label, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY DATE(created_at)
                    ORDER BY label
                    """,
                    (since,),
                ),
                "hourly": fetch_all(
                    cursor,
                    f"""
                    SELECT HOUR(created_at) AS label, COUNT(*) AS visits
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY HOUR(created_at)
                    ORDER BY label
                    """,
                    (since,),
                ),
                "target_pages": fetch_all(
                    cursor,
                    f"""
                    SELECT page_title, path, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s AND is_target_page = 1 AND {visit_filter}
                    GROUP BY page_title, path
                    ORDER BY visits DESC
                    """,
                    (since,),
                ),
                "top_clicks": top_clicks(days, 10, mode),
                "top_conversions": conversion_summary(days, 10, mode),
                "top_engagement": engagement_summary(days, 10, mode),
                "entry_pages": fetch_all(
                    cursor,
                    f"""
                    SELECT path, page_title, COUNT(*) AS visits
                    FROM (
                        SELECT path, page_title, ip_hash, created_at,
                               ROW_NUMBER() OVER (PARTITION BY ip_hash ORDER BY created_at ASC) AS row_num
                        FROM visitor_events
                        WHERE created_at >= %s AND {visit_filter}
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
                    f"""
                    SELECT path, page_title, COUNT(*) AS visits
                    FROM (
                        SELECT path, page_title, ip_hash, created_at,
                               ROW_NUMBER() OVER (PARTITION BY ip_hash ORDER BY created_at DESC) AS row_num
                        FROM visitor_events
                        WHERE created_at >= %s AND {visit_filter}
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
                    f"""
                    SELECT page_title, path, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY page_title, path
                    ORDER BY visits DESC
                    LIMIT 12
                    """,
                    (since,),
                ),
                "countries": fetch_all(
                    cursor,
                    f"""
                    SELECT COALESCE(NULLIF(country, ''), 'Unknown') AS label,
                           COUNT(*) AS visits,
                           COUNT(DISTINCT ip_hash) AS visitors,
                           MAX(latitude) AS latitude,
                           MAX(longitude) AS longitude
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY COALESCE(NULLIF(country, ''), 'Unknown')
                    ORDER BY visits DESC
                    LIMIT 20
                    """,
                    (since,),
                ),
                "locations": fetch_all(
                    cursor,
                    f"""
                    SELECT
                        COALESCE(NULLIF(city, ''), 'Unknown') AS city,
                        COALESCE(NULLIF(country, ''), 'Unknown') AS country,
                        COUNT(*) AS visits,
                        COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY COALESCE(NULLIF(city, ''), 'Unknown'), COALESCE(NULLIF(country, ''), 'Unknown')
                    ORDER BY visits DESC
                    LIMIT 12
                    """,
                    (since,),
                ),
                "devices": fetch_all(
                    cursor,
                    f"""
                    SELECT COALESCE(device_type, 'Unknown') AS label, COUNT(*) AS visits
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY COALESCE(device_type, 'Unknown')
                    ORDER BY visits DESC
                    """,
                    (since,),
                ),
                "browsers": fetch_all(
                    cursor,
                    f"""
                    SELECT COALESCE(browser, 'Unknown') AS label, COUNT(*) AS visits
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY COALESCE(browser, 'Unknown')
                    ORDER BY visits DESC
                    LIMIT 8
                    """,
                    (since,),
                ),
                "referrers": fetch_all(
                    cursor,
                    f"""
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
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY label
                    ORDER BY visits DESC
                    LIMIT 10
                    """,
                    (since,),
                ),
                "reports": report_data(days, mode),
                "live": realtime_data(mode),
                "recent_visits": fetch_visits(days=days, limit=15, mode=mode),
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


def report_data(days: int = 30, mode: str = "human") -> dict[str, list[dict[str, Any]]]:
    since = utc_since(days)
    visit_filter = traffic_condition(mode)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return {
                "daily": fetch_all(
                    cursor,
                    f"""
                    SELECT DATE(created_at) AS period, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY DATE(created_at)
                    ORDER BY period DESC
                    LIMIT 31
                    """,
                    (since,),
                ),
                "weekly": fetch_all(
                    cursor,
                    f"""
                    SELECT YEARWEEK(created_at, 1) AS period, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY YEARWEEK(created_at, 1)
                    ORDER BY period DESC
                    LIMIT 12
                    """,
                    (since,),
                ),
                "monthly": fetch_all(
                    cursor,
                    f"""
                    SELECT DATE_FORMAT(created_at, '%Y-%m') AS period, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY DATE_FORMAT(created_at, '%Y-%m')
                    ORDER BY period DESC
                    LIMIT 12
                    """,
                    (since,),
                ),
            }
        finally:
            cursor.close()


def realtime_data(mode: str = "human") -> dict[str, Any]:
    active_since = utc_now() - timedelta(minutes=15)
    visit_filter = traffic_condition(mode)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return {
                "active_visitors": _scalar(
                    cursor,
                    f"SELECT COUNT(DISTINCT ip_hash) FROM visitor_events WHERE created_at >= %s AND {visit_filter}",
                    (active_since,),
                ),
                "live_page_views": _scalar(
                    cursor,
                    f"SELECT COUNT(*) FROM visitor_events WHERE created_at >= %s AND {visit_filter}",
                    (active_since,),
                ),
                "active_sessions": _scalar(
                    cursor,
                    f"SELECT COUNT(DISTINCT COALESCE(session_id, ip_hash)) FROM visitor_events WHERE created_at >= %s AND {visit_filter}",
                    (active_since,),
                ),
                "current_locations": fetch_all(
                    cursor,
                    f"""
                    SELECT COALESCE(NULLIF(city, ''), 'Unknown') AS city,
                           COALESCE(NULLIF(country, ''), 'Unknown') AS country,
                           COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY COALESCE(NULLIF(city, ''), 'Unknown'), COALESCE(NULLIF(country, ''), 'Unknown')
                    ORDER BY visitors DESC
                    LIMIT 20
                    """,
                    (active_since,),
                ),
                "recent_page_views": fetch_visits(days=1, limit=25, mode=mode),
            }
        finally:
            cursor.close()


def geo_analytics_data(days: int = 30) -> dict[str, Any]:
    since = utc_since(days)
    visit_filter = traffic_condition("human")
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return {
                "countries": fetch_all(
                    cursor,
                    f"""
                    SELECT COALESCE(NULLIF(country, ''), 'Unknown') AS label,
                           COUNT(*) AS visits,
                           COUNT(DISTINCT ip_hash) AS visitors,
                           MAX(latitude) AS latitude,
                           MAX(longitude) AS longitude
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY COALESCE(NULLIF(country, ''), 'Unknown')
                    ORDER BY visitors DESC, visits DESC
                    LIMIT 50
                    """,
                    (since,),
                ),
                "cities": fetch_all(
                    cursor,
                    f"""
                    SELECT COALESCE(NULLIF(city, ''), 'Unknown') AS city,
                           COALESCE(NULLIF(country, ''), 'Unknown') AS country,
                           COUNT(*) AS visits,
                           COUNT(DISTINCT ip_hash) AS visitors
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY COALESCE(NULLIF(city, ''), 'Unknown'), COALESCE(NULLIF(country, ''), 'Unknown')
                    ORDER BY visitors DESC, visits DESC
                    LIMIT 50
                    """,
                    (since,),
                ),
            }
        finally:
            cursor.close()


def traffic_analytics_data(days: int = 30, mode: str = "human") -> dict[str, Any]:
    since = utc_since(days)
    visit_filter = traffic_condition(mode)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return {
                "mode": traffic_mode(mode),
                "daily": fetch_all(
                    cursor,
                    f"""
                    SELECT DATE(created_at) AS label,
                           COUNT(*) AS visits,
                           COUNT(DISTINCT ip_hash) AS visitors,
                           COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS sessions
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY DATE(created_at)
                    ORDER BY label
                    """,
                    (since,),
                ),
                "hourly": fetch_all(
                    cursor,
                    f"""
                    SELECT DATE_FORMAT(created_at, '%Y-%m-%d %H:00') AS label,
                           COUNT(*) AS visits,
                           COUNT(DISTINCT ip_hash) AS visitors,
                           COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS sessions
                    FROM visitor_events
                    WHERE created_at >= %s AND {visit_filter}
                    GROUP BY DATE_FORMAT(created_at, '%Y-%m-%d %H:00')
                    ORDER BY label
                    LIMIT 240
                    """,
                    (since,),
                ),
            }
        finally:
            cursor.close()


def bot_analytics_data(days: int = 30) -> dict[str, Any]:
    since = utc_since(days)
    bot_filter = traffic_condition("bot")
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            overview = _fetch_one(
                cursor,
                f"""
                SELECT COUNT(*) AS total_bot_visits,
                       COUNT(DISTINCT ip_hash) AS bot_ips,
                       COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS bot_sessions,
                       AVG(risk_score) AS average_risk_score
                FROM visitor_events
                WHERE created_at >= %s AND {bot_filter}
                """,
                (since,),
            )
            return {
                "overview": {
                    "total_bot_visits": int(overview.get("total_bot_visits") or 0),
                    "bot_ips": int(overview.get("bot_ips") or 0),
                    "bot_sessions": int(overview.get("bot_sessions") or 0),
                    "average_risk_score": int(overview.get("average_risk_score") or 0),
                },
                "top_bots": fetch_all(
                    cursor,
                    f"""
                    SELECT COALESCE(NULLIF(bot_name, ''), 'Unknown bot') AS label,
                           COUNT(*) AS visits,
                           COUNT(DISTINCT ip_hash) AS ips
                    FROM visitor_events
                    WHERE created_at >= %s AND {bot_filter}
                    GROUP BY COALESCE(NULLIF(bot_name, ''), 'Unknown bot')
                    ORDER BY visits DESC
                    LIMIT 25
                    """,
                    (since,),
                ),
                "volume": fetch_all(
                    cursor,
                    f"""
                    SELECT DATE(created_at) AS label, COUNT(*) AS visits, COUNT(DISTINCT ip_hash) AS ips
                    FROM visitor_events
                    WHERE created_at >= %s AND {bot_filter}
                    GROUP BY DATE(created_at)
                    ORDER BY label
                    """,
                    (since,),
                ),
                "bot_ips": visitor_ip_summary(days=days, limit=500, mode="bot"),
            }
        finally:
            cursor.close()


def session_viewer_data(days: int = 30, query: str = "", mode: str = "human", limit: int = 500) -> list[dict[str, Any]]:
    clauses = ["created_at >= %s", traffic_condition(mode)]
    values: list[Any] = [utc_since(days)]
    if query:
        like = f"%{query}%"
        clauses.append(
            "("
            "ip_address LIKE %s OR city LIKE %s OR country LIKE %s OR browser LIKE %s OR "
            "device_type LIKE %s OR visitor_classification LIKE %s OR bot_name LIKE %s OR isp LIKE %s"
            ")"
        )
        values.extend([like, like, like, like, like, like, like, like])
    values.append(max(1, min(limit, 2000)))
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            sessions = fetch_all(
                cursor,
                f"""
                SELECT COALESCE(session_id, ip_hash) AS session_id,
                       MAX(ip_address) AS ip_address,
                       MIN(created_at) AS started_at,
                       MAX(created_at) AS ended_at,
                       TIMESTAMPDIFF(SECOND, MIN(created_at), MAX(created_at)) AS duration_seconds,
                       COUNT(*) AS page_views,
                       COUNT(DISTINCT path) AS unique_pages,
                       CASE
                           WHEN SUM(({LEGACY_CLASSIFICATION_SQL}) = 'bot') > 0 THEN 'bot'
                           WHEN SUM(({LEGACY_CLASSIFICATION_SQL}) = 'suspicious') > 0 THEN 'suspicious'
                           ELSE 'human'
                       END AS visitor_classification,
                       MAX(is_bot) AS is_bot,
                       COALESCE(MAX(bot_name), '') AS bot_name,
                       MAX(risk_score) AS risk_score,
                       COALESCE(MAX(classification_reason), '') AS classification_reason,
                       COALESCE(MAX(browser), 'Unknown') AS browser,
                       COALESCE(MAX(device_type), 'Unknown') AS device_type,
                       COALESCE(MAX(country), 'Unknown') AS country,
                       COALESCE(MAX(city), 'Unknown') AS city,
                       COALESCE(MAX(isp), 'Unknown') AS isp
                FROM visitor_events
                WHERE {" AND ".join(clauses)}
                GROUP BY COALESCE(session_id, ip_hash)
                ORDER BY ended_at DESC
                LIMIT %s
                """,
                values,
            )
            for session in sessions:
                session["pages"] = fetch_all(
                    cursor,
                    """
                    SELECT created_at, path, page_title
                    FROM visitor_events
                    WHERE session_id = %s OR (session_id IS NULL AND ip_hash = %s)
                    ORDER BY created_at ASC
                    LIMIT 50
                    """,
                    (session["session_id"], session["session_id"]),
                )
            return sessions
        finally:
            cursor.close()


def top_clicks(days: int = 30, limit: int = 25, mode: str = "human") -> list[dict[str, Any]]:
    since = utc_since(days)
    event_filter = traffic_condition(mode)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                f"""
                SELECT COALESCE(NULLIF(element_text, ''), target_url, 'Unlabeled click') AS label,
                       path,
                       target_url,
                       COUNT(*) AS clicks,
                       COUNT(DISTINCT ip_hash) AS visitors,
                       COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS sessions
                FROM click_events
                WHERE created_at >= %s AND {event_filter}
                GROUP BY COALESCE(NULLIF(element_text, ''), target_url, 'Unlabeled click'), path, target_url
                ORDER BY clicks DESC
                LIMIT %s
                """,
                (since, max(1, min(limit, 100))),
            )
        finally:
            cursor.close()


def fetch_clicks(days: int = 30, query: str = "", limit: int = 500, mode: str = "all") -> list[dict[str, Any]]:
    clauses = ["created_at >= %s", traffic_condition(mode)]
    values: list[Any] = [utc_since(days)]
    if query:
        like = f"%{query}%"
        clauses.append(
            "("
            "ip_address LIKE %s OR path LIKE %s OR element_text LIKE %s OR target_url LIKE %s OR "
            "browser LIKE %s OR visitor_classification LIKE %s OR bot_name LIKE %s OR classification_reason LIKE %s"
            ")"
        )
        values.extend([like, like, like, like, like, like, like, like])
    values.append(max(1, min(limit, 1000)))
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                f"""
                SELECT id, created_at, session_id, ip_address, path, page_title,
                       element_text, element_type, element_id, element_classes,
                       target_url, referrer, user_agent, browser, device_type,
                       visitor_classification, is_bot, bot_name, risk_score,
                       classification_reason
                FROM click_events
                WHERE {" AND ".join(clauses)}
                ORDER BY created_at DESC
                LIMIT %s
                """,
                values,
            )
        finally:
            cursor.close()


def conversion_summary(days: int = 30, limit: int = 25, mode: str = "human") -> list[dict[str, Any]]:
    since = utc_since(days)
    event_filter = traffic_condition(mode)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                f"""
                SELECT conversion_type,
                       COALESCE(NULLIF(value_label, ''), target, conversion_type) AS label,
                       path,
                       COUNT(*) AS conversions,
                       COUNT(DISTINCT ip_hash) AS visitors,
                       COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS sessions
                FROM conversion_events
                WHERE created_at >= %s AND {event_filter}
                GROUP BY conversion_type, COALESCE(NULLIF(value_label, ''), target, conversion_type), path
                ORDER BY conversions DESC
                LIMIT %s
                """,
                (since, max(1, min(limit, 100))),
            )
        finally:
            cursor.close()


def fetch_conversions(days: int = 30, query: str = "", limit: int = 500, mode: str = "all") -> list[dict[str, Any]]:
    clauses = ["created_at >= %s", traffic_condition(mode)]
    values: list[Any] = [utc_since(days)]
    if query:
        like = f"%{query}%"
        clauses.append(
            "("
            "ip_address LIKE %s OR conversion_type LIKE %s OR path LIKE %s OR target LIKE %s OR "
            "value_label LIKE %s OR visitor_classification LIKE %s OR bot_name LIKE %s OR classification_reason LIKE %s"
            ")"
        )
        values.extend([like, like, like, like, like, like, like, like])
    values.append(max(1, min(limit, 1000)))
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                f"""
                SELECT id, created_at, session_id, ip_address, conversion_type, path,
                       page_title, target, value_label, referrer, browser, device_type,
                       visitor_classification, is_bot, bot_name, risk_score,
                       classification_reason
                FROM conversion_events
                WHERE {" AND ".join(clauses)}
                ORDER BY created_at DESC
                LIMIT %s
                """,
                values,
            )
        finally:
            cursor.close()


def engagement_summary(days: int = 30, limit: int = 25, mode: str = "human") -> list[dict[str, Any]]:
    since = utc_since(days)
    event_filter = traffic_condition(mode)
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                f"""
                SELECT path,
                       COALESCE(NULLIF(page_title, ''), path) AS label,
                       COUNT(*) AS samples,
                       COUNT(DISTINCT ip_hash) AS visitors,
                       AVG(active_seconds) AS average_active_seconds,
                       AVG(max_scroll_percent) AS average_scroll_percent
                FROM page_engagement_events
                WHERE created_at >= %s AND {event_filter}
                GROUP BY path, COALESCE(NULLIF(page_title, ''), path)
                ORDER BY average_active_seconds DESC
                LIMIT %s
                """,
                (since, max(1, min(limit, 100))),
            )
        finally:
            cursor.close()


def fetch_engagement(days: int = 30, query: str = "", limit: int = 500, mode: str = "all") -> list[dict[str, Any]]:
    clauses = ["created_at >= %s", traffic_condition(mode)]
    values: list[Any] = [utc_since(days)]
    if query:
        like = f"%{query}%"
        clauses.append(
            "("
            "ip_address LIKE %s OR path LIKE %s OR page_title LIKE %s OR browser LIKE %s OR "
            "visitor_classification LIKE %s OR bot_name LIKE %s OR classification_reason LIKE %s"
            ")"
        )
        values.extend([like, like, like, like, like, like, like])
    values.append(max(1, min(limit, 1000)))
    with mysql_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            return fetch_all(
                cursor,
                f"""
                SELECT id, created_at, session_id, ip_address, path, page_title,
                       active_seconds, max_scroll_percent, browser, device_type,
                       visitor_classification, is_bot, bot_name, risk_score,
                       classification_reason
                FROM page_engagement_events
                WHERE {" AND ".join(clauses)}
                ORDER BY created_at DESC
                LIMIT %s
                """,
                values,
            )
        finally:
            cursor.close()


def visitor_ip_summary(days: int = 365, query: str = "", limit: int = 1000, mode: str = "human") -> list[dict[str, Any]]:
    clauses = ["created_at >= %s", traffic_condition(mode)]
    values: list[Any] = [utc_since(days)]
    if query:
        like = f"%{query}%"
        clauses.append(
            "("
            "ip_address LIKE %s OR city LIKE %s OR country LIKE %s OR browser LIKE %s OR "
            "device_type LIKE %s OR visitor_classification LIKE %s OR bot_name LIKE %s OR "
            "classification_reason LIKE %s OR isp LIKE %s"
            ")"
        )
        values.extend([like, like, like, like, like, like, like, like, like])
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
                       COALESCE(NULLIF(visitor_classification, ''), 'human') AS visitor_classification,
                       MAX(is_bot) AS is_bot,
                       COALESCE(MAX(bot_name), '') AS bot_name,
                       MAX(risk_score) AS risk_score,
                       COALESCE(MAX(classification_reason), '') AS classification_reason,
                       COALESCE(NULLIF(city, ''), 'Unknown') AS city,
                       COALESCE(NULLIF(country, ''), 'Unknown') AS country,
                       COALESCE(NULLIF(browser, ''), 'Unknown') AS browser,
                       COALESCE(NULLIF(device_type, ''), 'Unknown') AS device_type,
                       MAX(isp) AS isp
                FROM visitor_events
                WHERE {" AND ".join(clauses)}
                GROUP BY ip_address,
                         COALESCE(NULLIF(visitor_classification, ''), 'human'),
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


def fetch_visits(days: int = 30, path: str = "", query: str = "", limit: int = 200, mode: str = "human") -> list[dict[str, Any]]:
    where_sql, values = build_visit_filters(days, path, query, mode)
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
                    session_id, time_spent_seconds, visitor_classification, is_bot,
                    bot_name, risk_score, classification_reason
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
                    conversions, human_visits, bot_visits, suspicious_visits, sessions,
                    average_session_seconds, geo_stats, bounce_rate, created_at, updated_at
                )
                SELECT
                    'daily',
                    event_day,
                    visits,
                    unique_visitors,
                    visits,
                    conversions,
                    human_visits,
                    bot_visits,
                    suspicious_visits,
                    sessions,
                    average_session_seconds,
                    COALESCE(geo.geo_stats, JSON_OBJECT()),
                    bounce_rate,
                    %s,
                    %s
                FROM (
                    SELECT
                        DATE(created_at) AS event_day,
                        COUNT(*) AS visits,
                        COUNT(DISTINCT ip_hash) AS unique_visitors,
                        SUM(path IN ('/job-oss-bss-engineer.html', '/jobs/oss-bss-engineer')) AS conversions,
                        SUM(({classification_sql}) = 'human') AS human_visits,
                        SUM(({classification_sql}) = 'bot') AS bot_visits,
                        SUM(({classification_sql}) = 'suspicious') AS suspicious_visits,
                        COUNT(DISTINCT COALESCE(session_id, ip_hash)) AS sessions,
                        0 AS average_session_seconds,
                        0 AS bounce_rate
                    FROM visitor_events
                    WHERE created_at >= %s
                    GROUP BY DATE(created_at)
                ) daily
                LEFT JOIN (
                    SELECT event_day,
                           JSON_OBJECTAGG(country_label, visits) AS geo_stats
                    FROM (
                        SELECT DATE(created_at) AS event_day,
                               COALESCE(NULLIF(country, ''), 'Unknown') AS country_label,
                               COUNT(*) AS visits
                        FROM visitor_events
                        WHERE created_at >= %s
                        GROUP BY DATE(created_at), COALESCE(NULLIF(country, ''), 'Unknown')
                    ) geo_counts
                    GROUP BY event_day
                ) geo ON geo.event_day = daily.event_day
                ON DUPLICATE KEY UPDATE
                    visitors = VALUES(visitors),
                    unique_visitors = VALUES(unique_visitors),
                    page_views = VALUES(page_views),
                    conversions = VALUES(conversions),
                    human_visits = VALUES(human_visits),
                    bot_visits = VALUES(bot_visits),
                    suspicious_visits = VALUES(suspicious_visits),
                    sessions = VALUES(sessions),
                    average_session_seconds = VALUES(average_session_seconds),
                    geo_stats = VALUES(geo_stats),
                    bounce_rate = VALUES(bounce_rate),
                    updated_at = VALUES(updated_at)
                """.format(classification_sql=LEGACY_CLASSIFICATION_SQL),
                (now, now, since, since),
            )
            return cursor.rowcount
        finally:
            cursor.close()
