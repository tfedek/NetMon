<?php
require_once __DIR__ . '/includes/bootstrap.php';
if (is_logged_in()) { header('Location: ' . APP_URL . '/index.php'); exit; }

$error = $success = $pwned_warning = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $db        = Database::getInstance()->getConnection();
    $full_name = trim($_POST['full_name'] ?? '');
    $email     = sanitize_email($_POST['email'] ?? '');
    $pass      = $_POST['password'] ?? '';
    $pass2     = $_POST['password2'] ?? '';

    if (!$full_name || !$email || !$pass || !$pass2) {
        $error = 'Sva polja su obavezna.';
    } elseif (strlen($full_name) < 2 || strlen($full_name) > 100) {
        $error = 'Ime mora biti između 2 i 100 karaktera.';
    } elseif (!validate_email($email)) {
        $error = 'Neispravna email adresa.';
//    } elseif (is_disposable_email($email)) {
//        $error = 'Privremeni email adrese nisu dozvoljene. Molimo koristite pravi email.';
//    } elseif (strlen($pass) < 8) {
        $error = 'Lozinka mora imati najmanje 8 karaktera.';
    } elseif (!preg_match('/[A-Z]/', $pass) || !preg_match('/[0-9]/', $pass)) {
        $error = 'Lozinka mora sadržati najmanje jedno veliko slovo i jedan broj.';
    } elseif ($pass !== $pass2) {
        $error = 'Lozinke se ne poklapaju.';
    } else {
        if (is_email_pwned($email)) {
            $pwned_warning = 'Upozorenje: Ovaj email je pronađen u bazi leakovanih podataka. Koristite jedinstvenu lozinku.';
        }
        $stmt = $db->prepare("SELECT id FROM users WHERE email = :email LIMIT 1");
        $stmt->bindParam(':email', $email, PDO::PARAM_STR);
        $stmt->execute();
        if ($stmt->rowCount() > 0) {
            $error = 'Ovaj email je već registrovan.';
        } else {
            $hash = password_hash($pass, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
            $role = 'user';
            $stmt = $db->prepare("INSERT INTO users (email, password, full_name, role) VALUES (:email, :password, :full_name, :role)");
            $stmt->bindParam(':email',     $email,     PDO::PARAM_STR);
            $stmt->bindParam(':password',  $hash,      PDO::PARAM_STR);
            $stmt->bindParam(':full_name', $full_name, PDO::PARAM_STR);
            $stmt->bindParam(':role',      $role,      PDO::PARAM_STR);
            $stmt->execute();
            $success = 'Nalog kreiran! Možete se <a href="' . APP_URL . '/login.php">prijaviti</a>.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="sr">
<head>
    <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
    <title>Registracija – <?= APP_NAME ?></title>
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
<div class="auth-wrapper">
    <div class="auth-card">
        <div class="text-center mb-4">
            <div class="auth-logo"><i class="bi bi-activity text-success"></i> NetMon</div>
            <p class="text-muted small mt-1">Kreirajte nalog</p>
        </div>
        <?php if ($error): ?><div class="nm-alert nm-alert-danger mb-3"><i class="bi bi-exclamation-triangle me-2"></i><?= clean($error) ?></div><?php endif; ?>
        <?php if ($pwned_warning): ?>
            <div class="nm-alert nm-alert-info mb-3">
                <i class="bi bi-exclamation-triangle me-2"></i><?= clean($pwned_warning) ?>
            </div>
        <?php endif; ?>
        <?php if ($success): ?><div class="nm-alert nm-alert-success mb-3"><i class="bi bi-check-circle me-2"></i><?= $success ?></div><?php endif; ?>
        <?php if (!$success): ?>
            <form method="POST" novalidate>
                <?= csrf_field() ?>
                <div class="mb-3">
                    <label class="form-label">Ime i prezime</label>
                    <input type="text" name="full_name" class="form-control" value="<?= clean($_POST['full_name'] ?? '') ?>" placeholder="Marko Petrovic" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Email adresa</label>
                    <input type="email" name="email" class="form-control" value="<?= clean($_POST['email'] ?? '') ?>" placeholder="vas@email.com" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Lozinka</label>
                    <input type="password" id="password" name="password" class="form-control" placeholder="Min 8 znakova, 1 veliko slovo, 1 broj" required>
                    <small id="pw-strength" class="form-text"></small>
                </div>
                <div class="mb-3">
                    <label class="form-label">Potvrdite lozinku</label>
                    <input type="password" name="password2" class="form-control" placeholder="••••••••" required>
                </div>
                <div class="nm-alert nm-alert-info mb-3" style="font-size:.82rem;">
                    <i class="bi bi-info-circle me-1"></i>
                    Novi nalozi dobijaju <strong>User</strong> rolu. Administrator dodeljuje Admin rolu.
                </div>
                <button type="submit" class="btn btn-nm-primary w-100"><i class="bi bi-person-plus me-2"></i>Kreiraj nalog</button>
            </form>
        <?php endif; ?>
        <hr class="divider my-3">
        <div class="text-center small">
            Već imate nalog? <a href="<?= APP_URL ?>/login.php" class="text-muted">Prijavite se</a>
        </div>
    </div>
</div>
<script
        src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"
        integrity="sha384-YvpcrYf0tY3lHB60NNkmXc5s9fDVZLESaAA55NDzOxhy9GkcIdslK1eN7N6jIeHz"
        crossorigin="anonymous"></script>
<script src="<?= APP_URL ?>/public/js/app.js" nonce="<?= csp_nonce() ?>"></script>
</body>
</html>