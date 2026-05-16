USE amtelkom_analytics;

ALTER TABLE visitor_events ADD COLUMN session_id CHAR(36) NULL;
ALTER TABLE visitor_events ADD COLUMN time_spent_seconds INT UNSIGNED NULL;
CREATE INDEX idx_session_created_at ON visitor_events (session_id, created_at);

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

SOURCE schema.sql;
