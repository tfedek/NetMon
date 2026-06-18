<?php
require_once __DIR__ . '/includes/bootstrap.php';
require_once __DIR__ . '/includes/webauthn.php';

if (is_logged_in()) {
    header('Location: ' . APP_URL . '/index.php');
    exit;
}

$db = Database::getInstance()->getConnection();
$error = '';

if (empty($_SESSION['pending_2fa_user_id'])) {
    header('Location: ' . APP_URL . '/login.php');
    exit;
}

$userId = (int)$_SESSION['pending_2fa_user_id'];

if (!empty($_SESSION['pending_2fa_time']) && time() - (int)$_SESSION['pending_2fa_time'] > 300) {
    unset(
            $_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_email'],
            $_SESSION['pending_2fa_name'], $_SESSION['pending_2fa_role'],
            $_SESSION['pending_2fa_sv'], $_SESSION['pending_2fa_time']
    );
    $_SESSION['logout_reason'] = '2FA sesija je istekla. Prijavite se ponovo.';
    header('Location: ' . APP_URL . '/login.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();

    $rawClientJson = $_POST['auth_json'] ?? '';

    if (!$rawClientJson) {
        $error = 'WebAuthn odgovor nije primljen.';
    } else {
        // Sad koristi PRAVU kriptografsku verifikaciju (potpis, rpIdHash,
        // challenge match, anti-replay, anti-clone signCount provera)
        // umesto pre - kada se samo provеravalo da credential_id postoji u bazi.
        $result = webauthn_authentication_verify($db, $userId, $rawClientJson);

        if ($result['ok']) {
            session_regenerate_safe();

            $_SESSION['user_id']         = $userId;
            $_SESSION['user_email']      = $_SESSION['pending_2fa_email'];
            $_SESSION['user_name']       = $_SESSION['pending_2fa_name'];
            $_SESSION['user_role']       = $_SESSION['pending_2fa_role'];
            $_SESSION['session_version'] = (int)$_SESSION['pending_2fa_sv'];
            $_SESSION['logged_in_at']    = time();

            unset(
                    $_SESSION['pending_2fa_user_id'], $_SESSION['pending_2fa_email'],
                    $_SESSION['pending_2fa_name'], $_SESSION['pending_2fa_role'],
                    $_SESSION['pending_2fa_sv'], $_SESSION['pending_2fa_time']
            );

            log_access($db, $userId, $_SESSION['user_email'], true);

            header('Location: ' . APP_URL . '/index.php');
            exit;
        }

        $error = $result['error'] ?? 'Sigurnosni ključ nije prihvaćen.';
        error_log("WebAuthn login neuspesan za user_id=$userId: $error");
    }
}

$options = webauthn_authentication_options($db, $userId);

if (empty($options['allowCredentials'])) {
    $_SESSION['logout_reason'] = 'Nema registrovanog sigurnosnog ključa.';
    header('Location: ' . APP_URL . '/login.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="sr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>2FA potvrda – <?= APP_NAME ?></title>

    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;500&display=swap" rel="stylesheet" nonce="<?= csp_nonce() ?>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" nonce="<?= csp_nonce() ?>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet" nonce="<?= csp_nonce() ?>">
    <link href="<?= APP_URL ?>/public/css/app.css" rel="stylesheet" nonce="<?= csp_nonce() ?>">
    <meta name="csrf-token" content="<?= csrf_token() ?>">
</head>
<body>
<div class="auth-wrapper">
    <div class="auth-card">
        <div class="text-center mb-4">
            <div class="auth-logo"><i class="bi bi-shield-lock text-success"></i> NetMon</div>
            <p class="text-muted small mt-1">Potvrda sigurnosnim ključem</p>
        </div>

        <?php if ($error): ?>
            <div class="nm-alert nm-alert-danger mb-3">
                <i class="bi bi-exclamation-triangle me-2"></i><?= clean($error) ?>
            </div>
        <?php endif; ?>

        <div class="nm-alert nm-alert-info mb-3">
            <i class="bi bi-key me-2"></i>
            Prijava za korisnika:<br>
            <strong><?= clean($_SESSION['pending_2fa_name'] ?? '') ?></strong><br>
            <span class="small"><?= clean($_SESSION['pending_2fa_email'] ?? '') ?></span>
        </div>

        <button id="webauthnBtn" type="button" class="btn btn-nm-primary w-100 mt-1">
            <i class="bi bi-usb-symbol me-2"></i>Potvrdi sigurnosnim ključem
        </button>

        <form id="authForm" method="POST" action="<?= APP_URL ?>/webauthn-login.php" style="display:none;">
            <?= csrf_field() ?>
            <input type="hidden" name="auth_json" id="authJson">
        </form>

        <hr class="divider my-3">

        <div class="text-center small">
            <a href="<?= APP_URL ?>/logout.php" class="text-muted">Prekini prijavu</a>
        </div>

        <div id="statusLog" class="mt-3 small" style="display:none; background:#0f172a; color:#38bdf8; padding:12px; border-radius:8px; font-family:monospace;"></div>
    </div>
</div>

<script nonce="<?= csp_nonce() ?>">
    const options = <?= json_encode($options, JSON_UNESCAPED_SLASHES) ?>;

    function base64urlToUint8Array(base64url) {
        let padding = '='.repeat((4 - base64url.length % 4) % 4);
        let base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
        let raw = atob(base64);
        let arr = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
        return arr;
    }

    function bufferToBase64url(buffer) {
        let bytes = new Uint8Array(buffer);
        let binary = '';
        for (let b of bytes) binary += String.fromCharCode(b);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    document.getElementById('webauthnBtn').addEventListener('click', async () => {
        const log = document.getElementById('statusLog');
        log.style.display = 'block';
        log.style.color = '#38bdf8';
        log.innerHTML = 'Pripremam WebAuthn login...<br>';

        try {
            const publicKey = {
                ...options,
                challenge: base64urlToUint8Array(options.challenge),
                allowCredentials: options.allowCredentials.map(c => ({ ...c, id: base64urlToUint8Array(c.id) }))
            };

            log.innerHTML += 'Dodirni sigurnosni ključ kada browser zatraži potvrdu...<br>';

            const assertion = await navigator.credentials.get({ publicKey });

            const payload = {
                id: assertion.id,
                rawId: bufferToBase64url(assertion.rawId),
                type: assertion.type,
                response: {
                    clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                    authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                    signature: bufferToBase64url(assertion.response.signature),
                    userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null
                }
            };

            document.getElementById('authJson').value = JSON.stringify(payload);

            log.innerHTML += 'Potvrda dobijena. Završavam prijavu...<br>';
            document.getElementById('authForm').submit();

        } catch (e) {
            log.style.color = '#f87171';
            log.innerHTML += 'GREŠKA: ' + e.name + ' - ' + e.message;
            console.error(e);
        }
    });
</script>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz"
        crossorigin="anonymous"></script></body>
</html>