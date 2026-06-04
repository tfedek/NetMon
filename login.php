<?php
require_once __DIR__ . '/includes/bootstrap.php';
if (is_logged_in()) { header('Location: ' . APP_URL . '/index.php'); exit; }

$logoutReason = $_SESSION['logout_reason'] ?? '';
unset($_SESSION['logout_reason']);
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    //Honeypot provera
    if (!empty($_POST['website'])) {
        header('Location: ' . APP_URL . '/login.php');
        exit;
    }
    $db    = Database::getInstance()->getConnection();
    $email = sanitize_email($_POST['email'] ?? '');
    $pass  = $_POST['password'] ?? '';

    if (!$email || !$pass) {
        $error = 'Unesite email i lozinku.';
    } else {
        $ip  = get_client_ip();
        $sec = LOGIN_LOCKOUT_TIME;
        $stmt = $db->prepare(
            "SELECT COUNT(*) FROM login_audit
             WHERE ip_address = :ip AND success = 0
             AND created_at > DATE_SUB(NOW(), INTERVAL :sec SECOND)"
        );
        $stmt->bindParam(':ip',  $ip,  PDO::PARAM_STR);
        $stmt->bindParam(':sec', $sec, PDO::PARAM_INT);
        $stmt->execute();

        if ((int)$stmt->fetchColumn() >= LOGIN_MAX_ATTEMPTS) {
            $error = 'Previše neuspelih pokušaja. Sačekajte 15 minuta.';
        } else {
            $stmt = $db->prepare(
                "SELECT id, email, password, full_name, role, session_version
                 FROM users WHERE email = :email AND is_active = 1 LIMIT 1"
            );
            $stmt->bindParam(':email', $email, PDO::PARAM_STR);
            $stmt->execute();
            $user = $stmt->fetch();

            if ($user && password_verify($pass, $user['password'])) {
                session_regenerate_safe();
                $_SESSION['user_id']         = $user['id'];
                $_SESSION['user_email']      = $user['email'];
                $_SESSION['user_name']       = $user['full_name'];
                $_SESSION['user_role']       = $user['role'];
                $_SESSION['session_version'] = (int)$user['session_version'];
                $_SESSION['logged_in_at']    = time();
                log_access($db, (int)$user['id'], $email, true);
                header('Location: ' . APP_URL . '/index.php');
                exit;
            } else {
                $error = 'Pogrešan email ili lozinka.';
                log_access($db, null, $email, false);
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="sr">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Prijava – <?= APP_NAME ?></title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;500&display=swap" rel="stylesheet" nonce="<?= csp_nonce() ?>">
<!--  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" nonce="--><?php //= csp_nonce() ?><!--">-->
<!--  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet" nonce="--><?php //= csp_nonce() ?><!--">-->
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
<div class="auth-wrapper">
  <div class="auth-card">
    <div class="text-center mb-4">
      <div class="auth-logo"><i class="bi bi-activity text-success"></i> NetMon</div>
      <p class="text-muted small mt-1">Network Location Monitor</p>
    </div>
    <?php if ($logoutReason): ?>
    <div class="nm-alert nm-alert-info mb-3"><i class="bi bi-info-circle me-2"></i><?= clean($logoutReason) ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
    <div class="nm-alert nm-alert-danger mb-3"><i class="bi bi-exclamation-triangle me-2"></i><?= clean($error) ?></div>
    <?php endif; ?>
    <form method="POST" action="<?= APP_URL ?>/login.php" novalidate>
      <?= csrf_field() ?>
        <input type="text" name="website" tabindex="-1" autocomplete="off" class=""
               style="position:absolute!important;left:-9999px!important;top:-9999px!important;width:0!important;height:0!important;opacity:0!important;border:none!important;padding:0!important;margin:0!important;">
      <div class="mb-3">
        <label class="form-label" for="email">Email adresa</label>
        <div class="input-group">
          <span class="input-group-text bg-dark border-secondary text-muted"><i class="bi bi-envelope"></i></span>
          <input type="email" id="email" name="email" class="form-control"
                 value="<?= clean($_POST['email'] ?? '') ?>" placeholder="vas@email.com" autocomplete="email" required>
        </div>
      </div>
      <div class="mb-3">
        <label class="form-label" for="password">Lozinka</label>
        <div class="input-group">
          <span class="input-group-text bg-dark border-secondary text-muted"><i class="bi bi-lock"></i></span>
          <input type="password" id="password" name="password" class="form-control"
                 placeholder="••••••••" autocomplete="current-password" required>
        </div>
      </div>
      <button type="submit" class="btn btn-nm-primary w-100 mt-1">
        <i class="bi bi-box-arrow-in-right me-2"></i>Prijavi se
      </button>
    </form>
    <hr class="divider my-3">
    <div class="d-flex justify-content-between small">
      <a href="<?= APP_URL ?>/forgot-password.php" class="text-muted">Zaboravili ste lozinku?</a>
      <a href="<?= APP_URL ?>/register.php" class="text-muted">Kreiraj nalog</a>
    </div>
  </div>
</div>
<!--<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js" nonce="--><?php //= csp_nonce() ?><!--"></script>-->
<script
        src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz"
        crossorigin="anonymous"></script>
</body>
</html>
