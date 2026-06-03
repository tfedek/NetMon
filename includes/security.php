<?php
// ── Session ──────────────────────────────────────────────────
function session_start_secure(): void {
    if (session_status() === PHP_SESSION_NONE) {
        session_set_cookie_params([
            'lifetime' => SESSION_LIFETIME,
            'path'     => '/',
            'secure'   => false,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        ini_set('session.use_strict_mode',  '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.gc_maxlifetime',   (string) SESSION_LIFETIME);
        session_start();
    }
}

function session_regenerate_safe(): void {
    session_regenerate_id(true);
}

/**
 * Proverava session_version u bazi.
 * Ako admin promeni rolu, session_version se povecava -> korisnik se odjavljuje.
 */
function verify_session_version(PDO $db): void {
    if (!is_logged_in()) return;
    $uid = current_user_id();
    $stmt = $db->prepare("SELECT session_version, role, is_active FROM users WHERE id = :id LIMIT 1");
    $stmt->bindParam(':id', $uid, PDO::PARAM_INT);
    $stmt->execute();
    $user = $stmt->fetch();

    if (!$user || !$user['is_active']) {
        force_logout('Vaš nalog je deaktiviran.');
    }
    if ((int)$user['session_version'] !== (int)($_SESSION['session_version'] ?? 0)) {
        force_logout('Vaša prava pristupa su promenjena. Molimo prijavite se ponovo.');
    }
    $_SESSION['user_role'] = $user['role'];
}

function force_logout(string $reason = ''): void {
    if ($reason) $_SESSION['logout_reason'] = $reason;
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time()-42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
    session_destroy();
    header('Location: ' . APP_URL . '/login.php');
    exit;
}

// ── CSRF ──────────────
/**
 * Generiše HMAC CSRF token vezan za konkretnu URL putanju.
 * Ovo je napredniji pristup od prostog random tokena —
 * token je jedinstven i za sesiju i za konkretnu stranicu.
 */
function csrf_generate(): string {
    if (empty($_SESSION['csrf_secret'])) {
        $_SESSION['csrf_secret'] = bin2hex(random_bytes(32));
    }
    // Token je HMAC vezan za trenutnu putanju
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    return hash_hmac('sha256', $path, $_SESSION['csrf_secret']);
}

function csrf_token(): string {
    return csrf_generate();
}

function csrf_field(): string {
    return '<input type="hidden" name="' . CSRF_TOKEN_NAME . '" value="' . htmlspecialchars(csrf_generate()) . '">';
}

function csrf_verify(): bool {
    $submitted = $_POST[CSRF_TOKEN_NAME] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if (empty($_SESSION['csrf_secret']) || empty($submitted)) return false;

    $path     = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    $expected = hash_hmac('sha256', $path, $_SESSION['csrf_secret']);
    return hash_equals($expected, $submitted);
}

function csrf_check(): void {
    if (!csrf_verify()) {
        http_response_code(403);
        die(json_encode(['error' => 'CSRF token validation failed.']));
    }
}

// ── CSP ───────────────────────────────────────────────────────
function send_security_headers(): void {
    $nonce = base64_encode(random_bytes(16));
    $_SESSION['csp_nonce'] = $nonce;
    header("Content-Security-Policy: default-src 'self'; "
        . "script-src 'self' 'nonce-{$nonce}' https://cdn.jsdelivr.net; "
        . "style-src 'self' 'nonce-{$nonce}' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        . "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
        . "img-src 'self' data: https:; connect-src 'self'; "
        . "frame-ancestors 'none'; base-uri 'self'; form-action 'self';");
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), camera=(), microphone=()');
}
function csp_nonce(): string { return $_SESSION['csp_nonce'] ?? ''; }

// ── Input ─────────────────────────────────────────────────────
function clean(mixed $v): string {
    return htmlspecialchars(trim((string)$v), ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
function sanitize_email(string $v): string|false { return filter_var(trim($v), FILTER_SANITIZE_EMAIL); }
function validate_email(string $v): bool { return (bool) filter_var($v, FILTER_VALIDATE_EMAIL); }
function validate_ip(string $v): bool { return (bool) filter_var($v, FILTER_VALIDATE_IP); }
function validate_hostname(string $v): bool {
    if (validate_ip($v)) return true;
    return (bool) preg_match('/^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/', $v);
}
function validate_port(mixed $v): bool { $p = (int)$v; return $p >= 1 && $p <= 65535; }

// ── JWT ──────────────────────────────────────────────────────
function jwt_encode(array $payload): string {
    $h = base64url_encode(json_encode(['typ'=>'JWT','alg'=>JWT_ALGO]));
    $payload['iat'] = time(); $payload['exp'] = time() + JWT_TTL;
    $b = base64url_encode(json_encode($payload));
    $s = base64url_encode(hash_hmac('sha256', "$h.$b", JWT_SECRET, true));
    return "$h.$b.$s";
}
function jwt_decode(string $token): array|false {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return false;
    [$h, $b, $s] = $parts;
    if (!hash_equals(base64url_encode(hash_hmac('sha256', "$h.$b", JWT_SECRET, true)), $s)) return false;
    $p = json_decode(base64url_decode($b), true);
    if (!$p || $p['exp'] < time()) return false;
    return $p;
}
function base64url_encode(string $d): string { return rtrim(strtr(base64_encode($d), '+/', '-_'), '='); }
function base64url_decode(string $d): string { return base64_decode(strtr($d, '-_', '+/') . str_repeat('=', (4-strlen($d)%4)%4)); }
function get_bearer_token(): ?string {
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (preg_match('/Bearer\s+(.+)/i', $auth, $m)) return $m[1];
    return null;
}

// ── Auth ──────────────────────────────────────────────────────
function is_logged_in(): bool { return !empty($_SESSION['user_id']); }
function require_login(): void {
    if (!is_logged_in()) { header('Location: ' . APP_URL . '/login.php'); exit; }
}
function require_admin(): void {
    require_login();
    if (!is_admin()) { header('Location: ' . APP_URL . '/index.php'); exit; }
}
function require_api_auth(): array {
    $token = get_bearer_token();
    if (!$token) json_die(401, 'Unauthorized. Bearer token required.');
    $payload = jwt_decode($token);
    if (!$payload) json_die(401, 'Invalid or expired token.');
    return $payload;
}
function current_user_id(): int    { return (int)($_SESSION['user_id']  ?? 0); }
function current_user_role(): string { return $_SESSION['user_role']     ?? 'user'; }
function current_user_name(): string { return $_SESSION['user_name']     ?? ''; }
function current_user_email(): string { return $_SESSION['user_email']   ?? ''; }
function is_admin(): bool            { return current_user_role() === 'admin'; }

// ── Response ──────────────────────────────────────────────────
function json_response(int $code, mixed $data): void {
    header('Content-Type: application/json; charset=UTF-8');
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}
function json_die(int $code, string $message, mixed $data = null): never {
    $body = ['success' => false, 'message' => $message];
    if ($data !== null) $body['data'] = $data;
    json_response($code, $body);
}
function json_ok(mixed $data, string $message = 'OK', int $code = 200): never {
    json_response($code, ['success' => true, 'message' => $message, 'data' => $data]);
}
//SSRF function is_private_ip(string $host): bool {
//    // Resolve hostname to IP if needed
//    $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
//    if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
//
//    // Block private, loopback, link-local and reserved ranges (SSRF zaštita)
//    return !filter_var($ip, FILTER_VALIDATE_IP,
//        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
//    );
//}