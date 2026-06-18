CREATE DATABASE IF NOT EXISTS netmon CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE netmon;

CREATE TABLE IF NOT EXISTS users (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    email           VARCHAR(150) NOT NULL UNIQUE,
    password        VARCHAR(255) NOT NULL,
    full_name       VARCHAR(100) NOT NULL DEFAULT '',
    role            ENUM('super_admin','admin','user') NOT NULL DEFAULT 'user',
    is_active       TINYINT(1)   NOT NULL DEFAULT 1,
    two_factor_required TINYINT(1) NOT NULL DEFAULT 0,
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

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id         INT UNSIGNED NOT NULL,
    credential_id   VARBINARY(255) NOT NULL UNIQUE,
    public_key      TEXT         NOT NULL,
    sign_count      INT UNSIGNED NOT NULL DEFAULT 0,
    aaguid          VARCHAR(36),
    nickname        VARCHAR(100) NOT NULL DEFAULT 'Security Key',
    last_used_at    DATETIME,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Privremeni storage za WebAuthn challenge tokom registracije/autentikacije
-- (kratak TTL, čisti se periodično ili po uspešnom korišćenju)
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED NOT NULL,
    challenge   VARCHAR(255) NOT NULL,
    type        ENUM('registration','authentication') NOT NULL,
    expires_at  DATETIME     NOT NULL,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- TOTP (Google Authenticator / Authy stil) - alternativa/dodatak FIDO2-u
CREATE TABLE IF NOT EXISTS totp_secrets (
    id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id       INT UNSIGNED NOT NULL UNIQUE,
    secret        VARCHAR(255) NOT NULL,   -- Base32 secret, enkriptovan na app nivou ako mozes
    confirmed_at  DATETIME,                -- NULL dok korisnik ne potvrdi prvi kod
    created_at    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Recovery/backup kodovi - generisani jednom pri 2FA setup-u, jednokratni
CREATE TABLE IF NOT EXISTS recovery_codes (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED NOT NULL,
    code_hash   VARCHAR(255) NOT NULL,   -- bcrypt hash koda, nikad plain text
    used_at     DATETIME,
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Bridge tabela: nakon uspesne lozinke, pre potvrde 2FA.
-- Sprecava da napadac sa samo lozinkom dobije pun pristup dok ceka 2FA.
CREATE TABLE IF NOT EXISTS pending_2fa (
    id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     INT UNSIGNED NOT NULL,
    token       VARCHAR(100) NOT NULL UNIQUE,  -- nasumicni token, cuva se u privremenom kolacicu
    expires_at  DATETIME     NOT NULL,         -- kratak TTL (npr. 5 min)
    created_at  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_locations_user    ON locations(user_id);
CREATE INDEX idx_checks_location   ON checks(location_id);
CREATE INDEX idx_checks_checked_at ON checks(checked_at);
CREATE INDEX idx_audit_user        ON login_audit(user_id);
CREATE INDEX idx_audit_created     ON login_audit(created_at);
CREATE INDEX idx_resets_token      ON password_resets(token);
CREATE INDEX idx_webauthn_user     ON webauthn_credentials(user_id);
CREATE INDEX idx_challenge_user    ON webauthn_challenges(user_id);
CREATE INDEX idx_challenge_expires ON webauthn_challenges(expires_at);
CREATE INDEX idx_recovery_user     ON recovery_codes(user_id);
CREATE INDEX idx_pending2fa_token  ON pending_2fa(token);
CREATE INDEX idx_pending2fa_expires ON pending_2fa(expires_at);
