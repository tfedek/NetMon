<?php
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/Database.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/device.php';
require_once __DIR__ . '/checker.php';
require_once __DIR__ . '/mailer.php';

session_start_secure();
send_security_headers();

// Proverava session_version na svakom requestu
if (is_logged_in()) {
    try {
        $db = Database::getInstance()->getConnection();
        verify_session_version($db);
    } catch (Exception $e) {
        error_log('Session verify error: ' . $e->getMessage());
    }
}
