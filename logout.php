<?php
require_once __DIR__ . '/includes/bootstrap.php';
$_SESSION = [];
$p = session_get_cookie_params();
setcookie(session_name(), '', time()-42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
session_destroy();
header('Location: ' . APP_URL . '/login.php');
exit;
