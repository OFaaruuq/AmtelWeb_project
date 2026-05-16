CREATE DATABASE IF NOT EXISTS amtelkom_analytics
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE amtelkom_analytics;

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
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS visitor_events (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    visit_uuid CHAR(36) NOT NULL,
    session_id CHAR(36) NULL,
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
    time_spent_seconds INT UNSIGNED NULL,
    is_target_page BOOLEAN NOT NULL DEFAULT FALSE,
    INDEX idx_created_at (created_at),
    INDEX idx_path_created_at (path, created_at),
    INDEX idx_ip_created_at (ip_hash, created_at),
    INDEX idx_target_created_at (is_target_page, created_at),
    INDEX idx_session_created_at (session_id, created_at),
    INDEX idx_class_created_at (visitor_classification, created_at),
    INDEX idx_bot_created_at (is_bot, created_at)
) ENGINE=InnoDB;

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
) ENGINE=InnoDB;

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
) ENGINE=InnoDB;

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
) ENGINE=InnoDB;

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
) ENGINE=InnoDB;

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
) ENGINE=InnoDB;

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
) ENGINE=InnoDB;

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
) ENGINE=InnoDB;

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
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS error_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME(6) NOT NULL,
    level VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    path VARCHAR(255),
    traceback TEXT,
    INDEX idx_error_logs_created_at (created_at),
    INDEX idx_error_logs_level (level, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS suspicious_activity_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME(6) NOT NULL,
    ip_address VARCHAR(45),
    event_type VARCHAR(120) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    details JSON NULL,
    INDEX idx_suspicious_created_at (created_at),
    INDEX idx_suspicious_ip (ip_address, created_at)
) ENGINE=InnoDB;

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
) ENGINE=InnoDB;
