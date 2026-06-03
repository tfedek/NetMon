<?php
require_once __DIR__ . '/includes/bootstrap.php';
require_admin();

$db     = Database::getInstance()->getConnection();
$uid    = current_user_id();
$action = $_GET['action'] ?? 'list';
$id     = (int)($_GET['id'] ?? 0);
$error  = $success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $name     = trim($_POST['name']        ?? '');
    $host     = trim($_POST['host']        ?? '');
    $port     = (int)($_POST['port']       ?? 80);
    $protocol = $_POST['protocol']         ?? 'tcp';
    $desc     = trim($_POST['description'] ?? '');
    $isActive = isset($_POST['is_active']) ? 1 : 0;
    $formId   = (int)($_POST['id']         ?? 0);

    if (!$name || strlen($name) > 100) {
        $error = 'Naziv je obavezan (max 100 karaktera).';
    } elseif (!validate_hostname($host) && !validate_ip($host)) {
        $error = 'Neispravan host ili IP adresa.';
    } elseif (!validate_port($port)) {
        $error = 'Port mora biti između 1 i 65535.';
    } elseif (!in_array($protocol, ['tcp','http','https','icmp'], true)) {
        $error = 'Neispravan protokol.';
    } elseif ($formId) {
        $stmt = $db->prepare('UPDATE locations SET name=:n,host=:h,port=:p,protocol=:pr,description=:d,is_active=:a WHERE id=:id');
        $stmt->bindParam(':n',  $name,     PDO::PARAM_STR);
        $stmt->bindParam(':h',  $host,     PDO::PARAM_STR);
        $stmt->bindParam(':p',  $port,     PDO::PARAM_INT);
        $stmt->bindParam(':pr', $protocol, PDO::PARAM_STR);
        $stmt->bindParam(':d',  $desc,     PDO::PARAM_STR);
        $stmt->bindParam(':a',  $isActive, PDO::PARAM_INT);
        $stmt->bindParam(':id', $formId,   PDO::PARAM_INT);
        $stmt->execute();
        $success = 'Lokacija ažurirana.'; $action = 'list';
    } else {
        $stmt = $db->prepare('INSERT INTO locations (user_id,name,host,port,protocol,description,is_active) VALUES (:uid,:n,:h,:p,:pr,:d,:a)');
        $stmt->bindParam(':uid', $uid,      PDO::PARAM_INT);
        $stmt->bindParam(':n',   $name,     PDO::PARAM_STR);
        $stmt->bindParam(':h',   $host,     PDO::PARAM_STR);
        $stmt->bindParam(':p',   $port,     PDO::PARAM_INT);
        $stmt->bindParam(':pr',  $protocol, PDO::PARAM_STR);
        $stmt->bindParam(':d',   $desc,     PDO::PARAM_STR);
        $stmt->bindParam(':a',   $isActive, PDO::PARAM_INT);
        $stmt->execute();
        $success = 'Lokacija dodata.'; $action = 'list';
    }
}

if ($action === 'delete' && $id) {
    $stmt = $db->prepare('DELETE FROM locations WHERE id = :id');
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();
    $success = 'Lokacija obrisana.'; $action = 'list';
}

$editLoc = null;
if ($action === 'edit' && $id) {
    $stmt = $db->prepare('SELECT * FROM locations WHERE id = :id LIMIT 1');
    $stmt->bindParam(':id', $id, PDO::PARAM_INT);
    $stmt->execute();
    $editLoc = $stmt->fetch();
    if (!$editLoc) { $error = 'Lokacija nije pronađena.'; $action = 'list'; }
}

$locs = $db->query("
    SELECT l.*, (SELECT COUNT(*) FROM checks WHERE location_id=l.id) as total_checks
    FROM locations l ORDER BY l.created_at DESC
")->fetchAll();

$title = 'Lokacije';
?>
<?php require __DIR__ . '/views/header.php'; ?>
<meta name="csrf-token" content="<?= csrf_token() ?>">

<div class="d-flex align-items-center justify-content-between mb-4">
  <span class="page-title"><i class="bi bi-hdd-network me-2"></i>Upravljanje lokacijama</span>
  <?php if ($action === 'list'): ?>
  <a href="?action=new" class="btn btn-nm-primary btn-sm"><i class="bi bi-plus-lg me-1"></i>Nova lokacija</a>
  <?php else: ?>
  <a href="<?= APP_URL ?>/locations.php" class="btn btn-nm-ghost btn-sm"><i class="bi bi-arrow-left me-1"></i>Nazad</a>
  <?php endif; ?>
</div>

<div id="flash-container">
<?php if ($error):   ?><div class="nm-alert nm-alert-danger mb-3"><i class="bi bi-exclamation-triangle me-2"></i><?= clean($error) ?></div><?php endif; ?>
<?php if ($success): ?><div class="nm-alert nm-alert-success mb-3"><i class="bi bi-check-circle me-2"></i><?= clean($success) ?></div><?php endif; ?>
</div>

<?php if ($action === 'new' || $action === 'edit'): ?>
<div class="nm-card" style="max-width:600px">
  <div class="nm-card-header"><span class="fw-500"><?= $action==='edit'?'Izmena lokacije':'Nova lokacija' ?></span></div>
  <form method="POST" novalidate>
    <?= csrf_field() ?>
    <?php if ($editLoc): ?><input type="hidden" name="id" value="<?= $editLoc['id'] ?>"><?php endif; ?>
    <div class="row g-3">
      <div class="col-12">
        <label class="form-label">Naziv *</label>
        <input type="text" name="name" class="form-control" required maxlength="100" value="<?= clean($editLoc['name'] ?? '') ?>" placeholder="npr. Kopernikova 53">
      </div>
      <div class="col-md-8">
        <label class="form-label">Host / IP *</label>
        <input type="text" name="host" class="form-control" required value="<?= clean($editLoc['host'] ?? '') ?>" placeholder="192.168.1.1 ili server.local">
      </div>
      <div class="col-md-4">
        <label class="form-label">Port *</label>
        <input type="number" name="port" class="form-control" required min="1" max="65535" value="<?= $editLoc['port'] ?? 80 ?>">
      </div>
      <div class="col-md-6">
        <label class="form-label">Protokol</label>
        <select name="protocol" class="form-select">
          <?php foreach (['tcp','http','https','icmp'] as $p): ?>
          <option value="<?= $p ?>" <?= ($editLoc['protocol']??'tcp')===$p?'selected':'' ?>><?= strtoupper($p) ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-md-6">
        <label class="form-label">Status</label>
        <div class="form-check form-switch mt-2">
          <input class="form-check-input" type="checkbox" name="is_active" id="is_active" <?= ($editLoc['is_active']??1)?'checked':'' ?>>
          <label class="form-check-label text-muted" for="is_active">Aktivna</label>
        </div>
      </div>
      <div class="col-12">
        <label class="form-label">Opis</label>
        <textarea name="description" class="form-control" rows="2" placeholder="Opcioni opis"><?= clean($editLoc['description'] ?? '') ?></textarea>
      </div>
      <div class="col-12 d-flex gap-2">
        <button type="submit" class="btn btn-nm-primary"><i class="bi bi-floppy me-2"></i><?= $action==='edit'?'Sačuvaj':'Dodaj' ?></button>
        <a href="<?= APP_URL ?>/locations.php" class="btn btn-nm-ghost">Otkaži</a>
      </div>
    </div>
  </form>
</div>
<?php else: ?>
<?php if (empty($locs)): ?>
<div class="nm-card text-center py-5">
  <i class="bi bi-hdd-network display-6 text-muted d-block mb-3"></i>
  <a href="?action=new" class="btn btn-nm-primary btn-sm">Dodaj prvu lokaciju</a>
</div>
<?php else: ?>
<div class="nm-card p-0">
  <div class="table-responsive">
    <table class="nm-table">
      <thead><tr><th>Naziv</th><th>Host</th><th>Port</th><th>Protokol</th><th>Status</th><th>Poslednja provera</th><th>Provere</th><th>Akcije</th></tr></thead>
      <tbody>
      <?php foreach ($locs as $loc): ?>
      <tr id="loc-row-<?= $loc['id'] ?>">
        <td class="fw-500"><?= clean($loc['name']) ?></td>
        <td class="text-mono" style="font-size:.82rem;color:var(--nm-blue)"><?= clean($loc['host']) ?></td>
        <td class="text-mono text-muted"><?= $loc['port'] ?></td>
        <td><span class="nm-badge nm-badge-unknown"><?= strtoupper($loc['protocol']) ?></span></td>
        <td><span class="nm-badge nm-badge-<?= $loc['status'] ?>"><span class="nm-dot nm-dot-<?= $loc['status'] ?>"></span><?= $loc['status'] ?></span></td>
        <td class="text-muted" style="font-size:.8rem"><?= $loc['last_checked'] ? date('d.m.Y H:i', strtotime($loc['last_checked'])) : '—' ?></td>
        <td class="text-mono text-muted" style="font-size:.8rem"><?= $loc['total_checks'] ?></td>
        <td>
          <div class="d-flex gap-1">
            <a href="?action=edit&id=<?= $loc['id'] ?>" class="btn btn-nm-ghost btn-sm py-1 px-2"><i class="bi bi-pencil"></i></a>
            <a href="<?= APP_URL ?>/check.php?id=<?= $loc['id'] ?>" class="btn btn-nm-ghost btn-sm py-1 px-2"><i class="bi bi-play"></i></a>
            <button class="btn btn-nm-danger btn-sm py-1 px-2" onclick="deleteLocation(<?= $loc['id'] ?>)"><i class="bi bi-trash"></i></button>
          </div>
        </td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>
<?php endif; ?>
<?php endif; ?>
<?php require __DIR__ . '/views/footer.php'; ?>
