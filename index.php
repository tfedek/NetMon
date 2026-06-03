<?php
require_once __DIR__ . '/includes/bootstrap.php';
require_login();
$db = Database::getInstance()->getConnection();

$stats = $db->query("
    SELECT COUNT(*) as total,
           SUM(status='online')  as online,
           SUM(status='offline') as offline,
           SUM(status='unknown') as unknown
    FROM locations
")->fetch();

$locs = $db->query("
    SELECT l.*,
           (SELECT response_time FROM checks WHERE location_id=l.id AND success=1 ORDER BY checked_at DESC LIMIT 1) as last_rt,
           (SELECT COUNT(*) FROM checks WHERE location_id=l.id AND checked_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)) as checks_24h,
           (SELECT SUM(success) FROM checks WHERE location_id=l.id AND checked_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)) as ok_24h
    FROM locations l
    ORDER BY status='offline' DESC, l.name ASC
")->fetchAll();

$title = 'Dashboard';
?>
<?php require __DIR__ . '/views/header.php'; ?>
<meta name="csrf-token" content="<?= csrf_token() ?>">

<div class="d-flex align-items-center justify-content-between mb-4">
  <span class="page-title"><i class="bi bi-grid-1x2 me-2"></i>Dashboard</span>
  <div class="d-flex gap-2">
    <button class="btn btn-nm-ghost btn-sm" onclick="location.reload()"><i class="bi bi-arrow-clockwise me-1"></i>Osvezi</button>
    <?php if (is_admin()): ?>
    <a href="<?= APP_URL ?>/locations.php?action=new" class="btn btn-nm-primary btn-sm"><i class="bi bi-plus-lg me-1"></i>Dodaj lokaciju</a>
    <?php endif; ?>
  </div>
</div>

<div class="row g-3 mb-4">
  <div class="col-6 col-md-3"><div class="stat-box"><div class="stat-val text-mono"><?= $stats['total'] ?></div><div class="stat-lbl">Ukupno</div></div></div>
  <div class="col-6 col-md-3"><div class="stat-box"><div class="stat-val text-success text-mono"><?= $stats['online'] ?></div><div class="stat-lbl">Online</div></div></div>
  <div class="col-6 col-md-3"><div class="stat-box"><div class="stat-val text-danger text-mono"><?= $stats['offline'] ?></div><div class="stat-lbl">Offline</div></div></div>
  <div class="col-6 col-md-3">
    <div class="stat-box">
      <?php $up = $stats['total'] > 0 ? round(($stats['online']/$stats['total'])*100,1) : 0;
            $uc = $up>=95?'text-success':($up>=80?'':'text-danger'); ?>
      <div class="stat-val <?= $uc ?> text-mono"><?= $up ?>%</div>
      <div class="stat-lbl">Dostupnost</div>
    </div>
  </div>
</div>

<div id="flash-container"></div>

<?php if (empty($locs)): ?>
<div class="nm-card text-center py-5">
  <i class="bi bi-hdd-network display-6 text-muted d-block mb-3"></i>
  <p class="text-muted mb-3">Nema lokacija.</p>
  <?php if (is_admin()): ?><a href="<?= APP_URL ?>/locations.php?action=new" class="btn btn-nm-primary btn-sm">Dodaj prvu lokaciju</a><?php endif; ?>
</div>
<?php else: ?>
<div class="row g-3">
<?php foreach ($locs as $loc):
  $s = $loc['status'];
  $up = $loc['checks_24h'] > 0 ? round(($loc['ok_24h']/$loc['checks_24h'])*100) : null;
?>
  <div class="col-12 col-sm-6 col-xl-4">
    <div class="loc-card <?= $s ?>" data-id="<?= $loc['id'] ?>">
      <div class="d-flex justify-content-between align-items-start mb-2">
        <div class="fw-500 text-truncate me-2" style="max-width:200px" title="<?= clean($loc['name']) ?>"><?= clean($loc['name']) ?></div>
        <span class="nm-badge nm-badge-<?= $s ?> flex-shrink-0"><span class="nm-dot nm-dot-<?= $s ?>"></span><?= $s ?></span>
      </div>
      <div class="loc-host mb-1"><?= clean($loc['host']) ?>:<?= $loc['port'] ?> <span class="text-muted ms-1 small">[<?= $loc['protocol'] ?>]</span></div>
      <?php if ($loc['description']): ?>
      <div class="text-muted" style="font-size:.78rem;margin-bottom:.5rem"><?= clean(mb_substr($loc['description'],0,60)) ?><?= mb_strlen($loc['description'])>60?'…':'' ?></div>
      <?php endif; ?>
      <div class="d-flex justify-content-between align-items-center mt-2">
        <div class="loc-rt">
          <?php if ($loc['last_rt']): ?><i class="bi bi-speedometer2 me-1"></i><?= round($loc['last_rt'],1) ?> ms<?php else: ?><span class="text-muted">—</span><?php endif; ?>
          <?php if ($up !== null): ?><span class="ms-2 text-muted"><?= $up ?>% / 24h</span><?php endif; ?>
        </div>
        <?php if (is_admin()): ?>
        <div class="d-flex gap-1">
          <a href="<?= APP_URL ?>/locations.php?action=edit&id=<?= $loc['id'] ?>" class="btn btn-nm-ghost btn-sm py-0 px-2"><i class="bi bi-pencil" style="font-size:.75rem"></i></a>
          <button class="btn btn-nm-danger btn-sm py-0 px-2" onclick="deleteLocation(<?= $loc['id'] ?>)"><i class="bi bi-trash" style="font-size:.75rem"></i></button>
        </div>
        <?php endif; ?>
      </div>
    </div>
  </div>
<?php endforeach; ?>
</div>
<?php endif; ?>
<?php require __DIR__ . '/views/footer.php'; ?>
