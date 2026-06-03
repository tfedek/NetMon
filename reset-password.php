<?php
require_once __DIR__ . '/includes/bootstrap.php';
if (is_logged_in()) { header('Location: ' . APP_URL . '/index.php'); exit; }

$db    = Database::getInstance()->getConnection();
$token = clean($_GET['token'] ?? '');
$error = $success = '';
$valid = false;
$reset = null;

if ($token) {
    $stmt = $db->prepare(
        "SELECT pr.*, u.email, u.id as uid FROM password_resets pr
         JOIN users u ON u.id = pr.user_id
         WHERE pr.token = :token AND pr.used = 0 AND pr.expires_at > NOW() LIMIT 1"
    );
    $stmt->bindParam(':token', $token, PDO::PARAM_STR);
    $stmt->execute();
    $reset = $stmt->fetch();
    $valid = (bool)$reset;
}

if (!$valid && $token) $error = 'Link je nevažeći ili je istekao.';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $valid) {
    csrf_check();
    $pass  = $_POST['password']  ?? '';
    $pass2 = $_POST['password2'] ?? '';
    if (strlen($pass) < 8 || !preg_match('/[A-Z]/', $pass) || !preg_match('/[0-9]/', $pass)) {
        $error = 'Lozinka mora imati min 8 znakova, 1 veliko slovo i 1 broj.';
    } elseif ($pass !== $pass2) {
        $error = 'Lozinke se ne poklapaju.';
    } else {
        $hash = password_hash($pass, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
        $stmt = $db->prepare("UPDATE users SET password = :pw, session_version = session_version + 1 WHERE id = :id");
        $stmt->bindParam(':pw', $hash,           PDO::PARAM_STR);
        $stmt->bindParam(':id', $reset['uid'],   PDO::PARAM_INT);
        $stmt->execute();
        $stmt = $db->prepare("UPDATE password_resets SET used = 1 WHERE token = :token");
        $stmt->bindParam(':token', $token, PDO::PARAM_STR);
        $stmt->execute();
        $success = 'Lozinka je promenjena! <a href="' . APP_URL . '/login.php">Prijavite se</a>.';
        $valid = false;
    }
}
?>
<!DOCTYPE html>
<html lang="sr">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Nova lozinka – <?= APP_NAME ?></title>
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;500&display=swap" rel="stylesheet" nonce="<?= csp_nonce() ?>">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" nonce="<?= csp_nonce() ?>">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet" nonce="<?= csp_nonce() ?>">
  <link href="<?= APP_URL ?>/public/css/app.css" rel="stylesheet" nonce="<?= csp_nonce() ?>">
</head>
<body>
<div class="auth-wrapper">
  <div class="auth-card">
    <div class="text-center mb-4">
      <div class="auth-logo"><i class="bi bi-activity text-success"></i> NetMon</div>
      <p class="text-muted small mt-1">Postavite novu lozinku</p>
    </div>
    <?php if ($error): ?><div class="nm-alert nm-alert-danger mb-3"><?= clean($error) ?></div><?php endif; ?>
    <?php if ($success): ?><div class="nm-alert nm-alert-success mb-3"><?= $success ?></div><?php endif; ?>
    <?php if ($valid): ?>
    <form method="POST" novalidate>
      <?= csrf_field() ?>
      <input type="hidden" name="token" value="<?= clean($token) ?>">
      <div class="mb-3">
        <label class="form-label">Nova lozinka</label>
        <input type="password" id="password" name="password" class="form-control" placeholder="Min 8 znakova, 1 veliko slovo, 1 broj" required>
        <small id="pw-strength" class="form-text"></small>
      </div>
      <div class="mb-3">
        <label class="form-label">Potvrdite lozinku</label>
        <input type="password" name="password2" class="form-control" placeholder="••••••••" required>
      </div>
      <button type="submit" class="btn btn-nm-primary w-100"><i class="bi bi-key me-2"></i>Promeni lozinku</button>
    </form>
    <?php elseif (!$success): ?>
    <p class="text-muted text-center small"><a href="<?= APP_URL ?>/forgot-password.php">Zatraži novi link</a></p>
    <?php endif; ?>
  </div>
</div>
<script src="<?= APP_URL ?>/public/js/app.js" nonce="<?= csp_nonce() ?>"></script>
</body>
</html>
