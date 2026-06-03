CREATE DATABASE IF NOT EXISTS netmon CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE netmon;

CREATE TABLE IF NOT EXISTS users (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email           VARCHAR(150) NOT NULL UNIQUE,
    password        VARCHAR(255) NOT NULL,
    full_name       VARCHAR(100) NOT NULL DEFAULT '',
    role            ENUM('admin','user') NOT NULL DEFAULT 'user',
    is_active       TINYINT(1)   NOT NULL DEFAULT 1,
    session_version INT UNSIGNED NOT NULL DEFAULT 1,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS password_resets (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED NOT NULL,
    token       VARCHAR(100) NOT NULL UNIQUE,
    expires_at  DATETIME     NOT NULL,
    used        TINYINT(1)   NOT NULL DEFAULT 0,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS locations (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id      INT UNSIGNED NOT NULL,
    name         VARCHAR(100) NOT NULL,
    host         VARCHAR(255) NOT NULL,
    port         SMALLINT UNSIGNED NOT NULL DEFAULT 80,
    protocol     ENUM('tcp','http','https','icmp') NOT NULL DEFAULT 'tcp',
    description  TEXT,
    is_active    TINYINT(1)   NOT NULL DEFAULT 1,
    status       ENUM('online','offline','unknown') NOT NULL DEFAULT 'unknown',
    last_checked DATETIME,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS checks (
    id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    location_id    INT UNSIGNED NOT NULL,
    success        TINYINT(1)   NOT NULL,
    response_time  FLOAT,
    error_message  VARCHAR(255),
    checked_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (location_id) REFERENCES locations(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS login_audit (
    id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id      INT UNSIGNED,
    email        VARCHAR(150),
    success      TINYINT(1)   NOT NULL DEFAULT 0,
    ip_address   VARCHAR(45)  NOT NULL,
    user_agent   TEXT,
    device_type  ENUM('desktop','tablet','mobile','unknown') NOT NULL DEFAULT 'unknown',
    os           VARCHAR(100),
    browser      VARCHAR(100),
    country      VARCHAR(100),
    city         VARCHAR(100),
    isp          VARCHAR(200),
    geo_raw      TEXT,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS email_failures (
    id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id    INT UNSIGNED,
    message    TEXT         NOT NULL,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE INDEX idx_locations_user    ON locations(user_id);
CREATE INDEX idx_checks_location   ON checks(location_id);
CREATE INDEX idx_checks_checked_at ON checks(checked_at);
CREATE INDEX idx_audit_user        ON login_audit(user_id);
CREATE INDEX idx_audit_created     ON login_audit(created_at);
CREATE INDEX idx_resets_token      ON password_resets(token);
