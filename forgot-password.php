<?php
require_once __DIR__ . '/includes/bootstrap.php';
if (is_logged_in()) { header('Location: ' . APP_URL . '/index.php'); exit; }

$error = $success = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $db    = Database::getInstance()->getConnection();
    $email = sanitize_email($_POST['email'] ?? '');

    if (!validate_email($email)) {
        $error = 'Unesite ispravnu email adresu.';
    } else {
        $stmt = $db->prepare("SELECT id, full_name FROM users WHERE email = :email AND is_active = 1 LIMIT 1");
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->execute();
        $user = $stmt->fetch();

        // Uvek isti odgovor – sprečava enumeraciju emailova
        $success = 'Ako taj email postoji u sistemu, link za reset je poslat.';

        if ($user) {
            $token = bin2hex(random_bytes(32));
            $stmt  = $db->prepare(
                "INSERT INTO password_resets (user_id, token, expires_at)
                 VALUES (:uid, :token, DATE_ADD(NOW(), INTERVAL 1 HOUR))"
            );
            $stmt->bindParam(':uid',   $user['id'], PDO::PARAM_INT);
            $stmt->bindParam(':token', $token,      PDO::PARAM_STR);
            $stmt->execute();

            $sent = send_reset_email($email, $user['full_name'], $token);

            // Loguj neuspelo slanje u bazu (profesorov addEmailFailure pattern)
            if (!$sent) {
                log_email_failure($db, (int)$user['id'],
                    "Reset email nije mogao biti poslat na: {$email}");
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="sr">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>Zaboravljena lozinka – <?= APP_NAME ?></title>
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
      <p class="text-muted small mt-1">Resetovanje lozinke</p>
    </div>
    <?php if ($error): ?><div class="nm-alert nm-alert-danger mb-3"><?= clean($error) ?></div><?php endif; ?>
    <?php if ($success): ?><div class="nm-alert nm-alert-success mb-3"><?= clean($success) ?></div><?php endif; ?>
    <?php if (!$success): ?>
    <form method="POST" novalidate>
      <?= csrf_field() ?>
      <div class="mb-3">
        <label class="form-label">Email adresa</label>
        <input type="email" name="email" class="form-control" placeholder="vas@email.com" required>
      </div>
      <button type="submit" class="btn btn-nm-primary w-100">
        <i class="bi bi-send me-2"></i>Pošalji link za reset
      </button>
    </form>
    <?php endif; ?>
    <hr class="divider my-3">
    <div class="text-center small">
      <a href="<?= APP_URL ?>/login.php" class="text-muted"><i class="bi bi-arrow-left me-1"></i>Nazad na prijavu</a>
    </div>
  </div>
</div>
</body>
</html>
