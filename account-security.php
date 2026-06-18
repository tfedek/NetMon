<?php
require_once __DIR__ . '/includes/bootstrap.php';
require_once __DIR__ . '/includes/webauthn.php';
// NAPOMENA: includes/twofactor.php (TOTP/recovery codes) namerno nije ucitan
// ovde - ta funkcionalnost ce biti dodata kad instaliramo spomky-labs/otphp
// paket. Trenutno ova stranica koristi samo FIDO2 (webauthn.php) i password change.

require_login();

$db = Database::getInstance()->getConnection();
$userId = current_user_id();

$msg = '';
$msgClass = '';
$registrationOptionsJson = null; // za JS, samo ako se eksplicitno trazi dodavanje kljuca

// ── POST handling ─────────────────────────────────────────────

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = $_POST['action'] ?? '';

    if ($action === 'change_password') {
        $currentPass = $_POST['current_password'] ?? '';
        $newPass     = $_POST['new_password'] ?? '';
        $confirmPass = $_POST['confirm_password'] ?? '';

        $stmt = $db->prepare("SELECT password FROM users WHERE id = :id LIMIT 1");
        $stmt->bindParam(':id', $userId, PDO::PARAM_INT);
        $stmt->execute();
        $row = $stmt->fetch();

        if (!$row || !password_verify($currentPass, $row['password'])) {
            $msg = 'Trenutna lozinka nije ispravna.';
            $msgClass = 'danger';
        } elseif (strlen($newPass) < 8) {
            $msg = 'Nova lozinka mora imati bar 8 karaktera.';
            $msgClass = 'danger';
        } elseif (!preg_match('/[A-Z]/', $newPass) || !preg_match('/[0-9]/', $newPass)) {
            $msg = 'Nova lozinka mora sadržati najmanje jedno veliko slovo i jedan broj.';
            $msgClass = 'danger';
        } elseif ($newPass !== $confirmPass) {
            $msg = 'Nova lozinka i potvrda se ne poklapaju.';
            $msgClass = 'danger';
        } elseif (password_verify($newPass, $row['password'])) {
            $msg = 'Nova lozinka mora biti različita od trenutne.';
            $msgClass = 'danger';
        } else {
            $newHash = password_hash($newPass, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
            // session_version + 1 -> sve POSTOJEĆE sesije (na drugim uređajima) se invalidiraju,
            // standardna praksa nakon promene lozinke.
            $stmt = $db->prepare("UPDATE users SET password = :pw, session_version = session_version + 1 WHERE id = :id");
            $stmt->bindParam(':pw', $newHash, PDO::PARAM_STR);
            $stmt->bindParam(':id', $userId, PDO::PARAM_INT);
            $stmt->execute();

            // Trenutna sesija ostaje aktivna - ažuriramo session_version lokalno
            // da ne izbacimo korisnika koji je upravo promenio svoju lozinku.
            $_SESSION['session_version']++;

            $msg = 'Lozinka je uspešno promenjena. Ostale aktivne sesije su odjavljene.';
            $msgClass = 'success';
        }
    }

    elseif ($action === 'webauthn_verify') {
        $rawClientJson = $_POST['assert_json'] ?? '';
        $nickname = trim($_POST['nickname'] ?? '') ?: 'Security Key';
        $nickname = mb_substr($nickname, 0, 100);

        if (!$rawClientJson) {
            $msg = 'WebAuthn odgovor nije primljen.';
            $msgClass = 'danger';
        } else {
            $result = webauthn_registration_verify($db, $userId, $rawClientJson, $nickname);
            if ($result['ok']) {
                $msg = 'Sigurnosni ključ "' . $nickname . '" je uspešno dodat.';
                $msgClass = 'success';
            } else {
                $msg = 'Registracija ključa nije uspela: ' . $result['error'];
                $msgClass = 'danger';
            }
        }
    }

    elseif ($action === 'webauthn_remove') {
        $credId = (int)($_POST['credential_id'] ?? 0);
        if ($credId) {
            webauthn_remove_credential($db, $userId, $credId);
            $msg = 'Sigurnosni ključ je uklonjen.';
            $msgClass = 'success';
        }
    }
}

// ── Podaci za prikaz ──────────────────────────────────────────

$credentials = webauthn_list_credentials($db, $userId);

$stmt = $db->prepare("SELECT full_name, email, role, two_factor_required FROM users WHERE id = :id LIMIT 1");
$stmt->bindParam(':id', $userId, PDO::PARAM_INT);
$stmt->execute();
$user = $stmt->fetch();

$twoFactorRequired = (bool)($user['two_factor_required'] ?? false);
$hasAnyCredential = count($credentials) > 0;

// Ako je trazena registracija novog kljuca (preko ?add_key=1), generisi opcije
$wantsAddKey = isset($_GET['add_key']);
if ($wantsAddKey) {
    try {
        $registrationOptionsJson = webauthn_registration_options($db, $userId, $user['email'], $user['full_name']);
    } catch (Throwable $e) {
        $msg = 'Greška pri pripremi registracije ključa: ' . $e->getMessage();
        $msgClass = 'danger';
        $wantsAddKey = false;
    }
}
?>
<!DOCTYPE html>
<html lang="sr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>Bezbednost naloga – <?= APP_NAME ?></title>

    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;500&display=swap" rel="stylesheet" nonce="<?= csp_nonce() ?>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH"
          crossorigin="anonymous">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"
          rel="stylesheet"
          integrity="sha384-XGjxtQfXaH2tnPFa9x+ruJTuLE3Aa6LhHSWRr1XeTyhezb4abCG4ccI5AkVDxqC+"
          crossorigin="anonymous">
    <link href="<?= APP_URL ?>/public/css/app.css" rel="stylesheet" nonce="<?= csp_nonce() ?>">
    <meta name="csrf-token" content="<?= csrf_token() ?>">
</head>
<body>
<?php include __DIR__ . '/views/header.php'; ?>

<main class="container py-4" style="max-width: 720px;">
    <h4 class="mb-4"><i class="bi bi-shield-lock me-2"></i>Bezbednost naloga</h4>

    <?php if ($msg): ?>
        <div class="nm-alert nm-alert-<?= $msgClass === 'success' ? 'success' : 'danger' ?> mb-4">
            <i class="bi bi-<?= $msgClass === 'success' ? 'check-circle' : 'exclamation-triangle' ?> me-2"></i><?= clean($msg) ?>
        </div>
    <?php endif; ?>

    <!-- Promena lozinke -->
    <div class="nm-card mb-4">
        <div class="nm-card-header px-3 pt-3 pb-2">
            <span class="fw-500"><i class="bi bi-key me-2"></i>Promena lozinke</span>
        </div>
        <div class="p-3">
            <form method="POST" novalidate>
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="change_password">

                <div class="mb-3">
                    <label class="form-label">Trenutna lozinka</label>
                    <input type="password" name="current_password" class="form-control" autocomplete="current-password" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Nova lozinka</label>
                    <input type="password" name="new_password" class="form-control" autocomplete="new-password" placeholder="Min 8 znakova, 1 veliko slovo, 1 broj" minlength="8" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Potvrdi novu lozinku</label>
                    <input type="password" name="confirm_password" class="form-control" autocomplete="new-password" minlength="8" required>
                </div>

                <button type="submit" class="btn btn-nm-primary">
                    <i class="bi bi-check-lg me-2"></i>Promeni lozinku
                </button>
                <p class="text-muted small mt-2 mb-0">Promena lozinke će odjaviti sve ostale aktivne sesije (na drugim uređajima).</p>
            </form>
        </div>
    </div>

    <!-- FIDO2 / Security Keys -->
    <div class="nm-card mb-4">
        <div class="nm-card-header px-3 pt-3 pb-2 d-flex justify-content-between align-items-center">
            <span class="fw-500"><i class="bi bi-usb-symbol me-2"></i>Sigurnosni ključevi (FIDO2)</span>
            <?php if ($twoFactorRequired): ?>
                <span class="nm-badge" style="background:rgba(248,81,73,.15);color:#f85149;border:1px solid rgba(248,81,73,.3)">obavezno za vašu rolu</span>
            <?php endif; ?>
        </div>
        <div class="p-3">
            <?php if (empty($credentials)): ?>
                <p class="text-muted small mb-3">Nemate registrovan nijedan sigurnosni ključ.</p>
            <?php else: ?>
                <div class="table-responsive mb-3">
                    <table class="nm-table">
                        <thead><tr><th>Naziv</th><th>Dodat</th><th>Poslednje korišćenje</th><th></th></tr></thead>
                        <tbody>
                        <?php foreach ($credentials as $cred): ?>
                            <tr>
                                <td class="fw-500"><?= clean($cred['nickname']) ?></td>
                                <td class="small text-muted"><?= date('d.m.Y H:i', strtotime($cred['created_at'])) ?></td>
                                <td class="small text-muted"><?= $cred['last_used_at'] ? date('d.m.Y H:i', strtotime($cred['last_used_at'])) : 'nikad' ?></td>
                                <td>
                                    <form method="POST" onsubmit="return confirm('Ukloniti ključ &quot;<?= clean($cred['nickname']) ?>&quot;?')">
                                        <?= csrf_field() ?>
                                        <input type="hidden" name="action" value="webauthn_remove">
                                        <input type="hidden" name="credential_id" value="<?= $cred['id'] ?>">
                                        <button type="submit" class="btn btn-nm-ghost btn-sm py-1 px-2" title="Ukloni">
                                            <i class="bi bi-trash3"></i>
                                        </button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>

            <div class="mb-3">
                <label class="form-label small">Naziv novog ključa</label>
                <input type="text" id="newKeyNickname" class="form-control" value="Moj Security Key" style="max-width: 320px;">
            </div>
            <a id="addKeyBtn" href="<?= APP_URL ?>/account-security.php?add_key=1#" class="btn btn-nm-primary">
                <i class="bi bi-plus-lg me-2"></i>Dodaj sigurnosni ključ
            </a>

            <div id="webauthnStatus" class="mt-3 small" style="display:none; background:#0f172a; color:#38bdf8; padding:12px; border-radius:8px; font-family:monospace;"></div>

            <form id="webauthnAddForm" method="POST" style="display:none;">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="webauthn_verify">
                <input type="hidden" name="assert_json" id="assertJsonInput">
                <input type="hidden" name="nickname" id="nicknameHiddenInput">
            </form>
        </div>
    </div>
</main>

<script nonce="<?= csp_nonce() ?>">
    function b64urlToBuf(b64url) {
        const pad = '='.repeat((4 - b64url.length % 4) % 4);
        const b64 = (b64url + pad).replace(/-/g, '+').replace(/_/g, '/');
        const raw = atob(b64);
        const arr = new Uint8Array(raw.length);
        for (let i = 0; i < raw.length; i++) arr[i] = raw.charCodeAt(i);
        return arr;
    }
    function bufToB64url(buf) {
        const bytes = new Uint8Array(buf);
        let bin = '';
        for (const b of bytes) bin += String.fromCharCode(b);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    document.getElementById('addKeyBtn').addEventListener('click', (e) => {
        // Sacuvaj naziv u localStorage NIJE opcija (zabranjeno u ovom okruzenju za
        // produkcioni JS, ali ovde je server-rendered PHP stranica, ne artifact -
        // localStorage je ok za cisto kozmeticko cuvanje izmedju reload-a).
        const nickname = document.getElementById('newKeyNickname').value || 'Security Key';
        sessionStorage.setItem('netmon_pending_key_nickname', nickname);
    });

    // Vrati upisani nickname nakon reload-a (add_key=1 stranica)
    (function restoreNickname() {
        const saved = sessionStorage.getItem('netmon_pending_key_nickname');
        if (saved) document.getElementById('newKeyNickname').value = saved;
    })();

    <?php if ($wantsAddKey && $registrationOptionsJson): ?>
    // Opcije su već generisane server-side (jer je ?add_key=1 u URL-u) - pokreni odmah.
    (async () => {
        const status = document.getElementById('webauthnStatus');
        status.style.display = 'block';
        status.style.color = '#38bdf8';
        status.innerHTML = 'Dodirni sigurnosni ključ kada browser zatraži...<br>';

        const opts = <?= json_encode($registrationOptionsJson) ?>;

        try {
            const publicKey = {
                ...opts,
                challenge: b64urlToBuf(opts.challenge),
                user: { ...opts.user, id: b64urlToBuf(opts.user.id) },
                excludeCredentials: (opts.excludeCredentials || []).map(c => ({ ...c, id: b64urlToBuf(c.id) }))
            };

            const credential = await navigator.credentials.create({ publicKey });

            const payload = {
                id: credential.id,
                rawId: bufToB64url(credential.rawId),
                type: credential.type,
                response: {
                    clientDataJSON: bufToB64url(credential.response.clientDataJSON),
                    attestationObject: bufToB64url(credential.response.attestationObject),
                }
            };

            document.getElementById('assertJsonInput').value = JSON.stringify(payload);
            document.getElementById('nicknameHiddenInput').value = document.getElementById('newKeyNickname').value || 'Security Key';
            sessionStorage.removeItem('netmon_pending_key_nickname');

            status.innerHTML += 'Šaljem na verifikaciju...';
            document.getElementById('webauthnAddForm').submit();

        } catch (e) {
            status.style.color = '#f87171';
            status.innerHTML += 'GREŠKA: ' + e.name + ' - ' + e.message;
        }
    })();
    <?php endif; ?>
</script>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz"
        crossorigin="anonymous"></script>
</body>
</html>