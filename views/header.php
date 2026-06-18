<?php
$title = $title ?? APP_NAME;
$nonce = csp_nonce();
$role  = current_user_role();
$name  = current_user_name();
?>
<!DOCTYPE html>
<html lang="sr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?= htmlspecialchars($title) ?> – <?= APP_NAME ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet" nonce="<?= $nonce ?>">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css"
          rel="stylesheet"
          integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH"
          crossorigin="anonymous">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css"
          rel="stylesheet"
          integrity="sha384-XGjxtQfXaH2tnPFa9x+ruJTuLE3Aa6LhHSWRr1XeTyhezb4abCG4ccI5AkVDxqC+"
          crossorigin="anonymous">
    <link href="<?= APP_URL ?>/public/css/app.css" rel="stylesheet" nonce="<?= $nonce ?>">
    <script nonce="<?= $nonce ?>">const appUrl = '<?= APP_URL ?>';</script>
</head>
<body>
<?php if (is_logged_in()): ?>
    <nav class="navbar navbar-dark nm-navbar">
        <div class="container-fluid">
            <a class="navbar-brand d-flex align-items-center gap-2" href="<?= APP_URL ?>/index.php">
                <i class="bi bi-activity text-success"></i>
                <span class="font-mono fw-bold">NetMon</span>
            </a>
            <div class="d-flex align-items-center gap-3">
                <a href="<?= APP_URL ?>/index.php" class="nav-link text-secondary">
                    <i class="bi bi-grid-1x2"></i> Dashboard
                </a>
                <?php if (is_admin()): ?>
                    <a href="<?= APP_URL ?>/locations.php" class="nav-link text-secondary">
                        <i class="bi bi-hdd-network"></i> Lokacije
                    </a>
                    <a href="<?= APP_URL ?>/admin.php" class="nav-link text-secondary">
                        <i class="bi bi-shield-lock"></i> Admin
                    </a>
                <?php endif; ?>
                <div class="vr opacity-25"></div>
                <span class="text-secondary small">
        <?= clean($name) ?>
        <span class="nm-badge ms-1 <?= ($role==='user') ? 'nm-badge-unknown' : '' ?>"
              style="<?= $role==='super_admin' ? 'background:rgba(248,81,73,.15);color:#f85149;border:1px solid rgba(248,81,73,.3)' : ($role==='admin' ? 'background:rgba(188,140,255,.15);color:#bc8cff;border:1px solid rgba(188,140,255,.3)' : '') ?>">
          <?= $role==='super_admin' ? 'super admin' : $role ?>
        </span>
      </span>
                <a href="<?= APP_URL ?>/account-security.php" class="nav-link text-secondary">
                    <i class="bi bi-person-lock"></i> Bezbednost
                </a>
                <a href="<?= APP_URL ?>/logout.php" class="btn btn-sm btn-outline-danger">Odjava</a>
            </div>
        </div>
    </nav>
<?php endif; ?>
<main class="container-fluid px-4 py-4">