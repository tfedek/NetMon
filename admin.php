<?php
require_once __DIR__ . '/includes/bootstrap.php';
require_admin();

$db  = Database::getInstance()->getConnection();
$tab = $_GET['tab'] ?? 'audit';
$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $tab === 'users') {
    csrf_check();
    $action = $_POST['action'] ?? '';
    $userId = (int)($_POST['user_id'] ?? 0);

    if ($userId && $userId !== current_user_id()) {
        if ($action === 'toggle') {
            $stmt = $db->prepare('UPDATE users SET is_active = !is_active, session_version = session_version + 1 WHERE id = :id');
            $stmt->bindParam(':id', $userId, PDO::PARAM_INT);
            $stmt->execute();
            $msg = 'Status korisnika promenjen. Sesija invalidisana.';
        } elseif ($action === 'make_admin') {
            $role = 'admin';
            $stmt = $db->prepare('UPDATE users SET role = :role, session_version = session_version + 1 WHERE id = :id');
            $stmt->bindParam(':role', $role,   PDO::PARAM_STR);
            $stmt->bindParam(':id',   $userId, PDO::PARAM_INT);
            $stmt->execute();
            $msg = 'Korisnik je sada Admin. Mora se ponovo prijaviti.';
        } elseif ($action === 'make_user') {
            $role = 'user';
            $stmt = $db->prepare('UPDATE users SET role = :role, session_version = session_version + 1 WHERE id = :id');
            $stmt->bindParam(':role', $role,   PDO::PARAM_STR);
            $stmt->bindParam(':id',   $userId, PDO::PARAM_INT);
            $stmt->execute();
            $msg = 'Korisnik vraćen na User rolu. Mora se ponovo prijaviti.';
        }
    }
}

$audit = $users = $stats = [];

if ($tab === 'audit') {
    $audit = $db->query("SELECT la.*, u.full_name FROM login_audit la LEFT JOIN users u ON u.id=la.user_id ORDER BY la.created_at DESC LIMIT 200")->fetchAll();
}
if ($tab === 'users') {
    $users = $db->query("
        SELECT u.*, COUNT(DISTINCT l.id) as location_count, MAX(la.created_at) as last_login
        FROM users u
        LEFT JOIN locations l ON l.user_id=u.id
        LEFT JOIN login_audit la ON la.user_id=u.id AND la.success=1
        GROUP BY u.id ORDER BY u.role DESC, u.created_at ASC
    ")->fetchAll();
}
if ($tab === 'stats') {
    $stats['checks_today']  = $db->query("SELECT COUNT(*) FROM checks WHERE checked_at >= CURDATE()")->fetchColumn();
    $stats['checks_week']   = $db->query("SELECT COUNT(*) FROM checks WHERE checked_at >= DATE_SUB(NOW(),INTERVAL 7 DAY)")->fetchColumn();
    $stats['success_rate']  = $db->query("SELECT ROUND(AVG(success)*100,1) FROM checks WHERE checked_at >= DATE_SUB(NOW(),INTERVAL 7 DAY)")->fetchColumn();
    $stats['avg_rt']        = $db->query("SELECT ROUND(AVG(response_time),1) FROM checks WHERE success=1 AND checked_at >= DATE_SUB(NOW(),INTERVAL 7 DAY)")->fetchColumn();
    $stats['devices']       = $db->query("SELECT device_type, COUNT(*) as cnt FROM login_audit GROUP BY device_type ORDER BY cnt DESC")->fetchAll();
    $stats['top_countries'] = $db->query("SELECT country, COUNT(*) as cnt FROM login_audit WHERE country!='' GROUP BY country ORDER BY cnt DESC LIMIT 10")->fetchAll();
    $stats['email_failures']= $db->query("SELECT ef.*, u.full_name FROM email_failures ef LEFT JOIN users u ON u.id=ef.user_id ORDER BY ef.created_at DESC LIMIT 20")->fetchAll();
}

$title = 'Admin Panel';
?>
<?php require __DIR__ . '/views/header.php'; ?>
<meta name="csrf-token" content="<?= csrf_token() ?>">

<div class="d-flex align-items-center justify-content-between mb-4">
  <span class="page-title"><i class="bi bi-shield-lock me-2"></i>Admin Panel</span>
</div>

<?php if ($msg): ?><div class="nm-alert nm-alert-success mb-3"><i class="bi bi-check-circle me-2"></i><?= clean($msg) ?></div><?php endif; ?>

<div class="d-flex gap-1 mb-4">
  <?php foreach (['audit'=>'Access Log','users'=>'Korisnici','stats'=>'Statistike'] as $k=>$lbl): ?>
  <a href="?tab=<?= $k ?>" class="btn btn-sm <?= $tab===$k?'btn-nm-primary':'btn-nm-ghost' ?>"><?= $lbl ?></a>
  <?php endforeach; ?>
</div>

<?php if ($tab === 'audit'): ?>
<div class="nm-card p-0">
  <div class="nm-card-header px-3 pt-3 pb-2">
    <span class="fw-500">Login audit log</span><span class="text-muted ms-2 small">(poslednjih 200)</span>
  </div>
  <div class="table-responsive">
    <table class="nm-table">
      <thead><tr><th>Vreme</th><th>Korisnik</th><th>Rezultat</th><th>IP</th><th>Uređaj</th><th>OS</th><th>Browser</th><th>Zemlja</th><th>Grad</th><th>ISP</th></tr></thead>
      <tbody>
      <?php foreach ($audit as $r): ?>
      <tr>
        <td class="text-mono" style="font-size:.78rem;white-space:nowrap"><?= date('d.m.Y H:i:s',strtotime($r['created_at'])) ?></td>
        <td style="font-size:.82rem"><?= $r['full_name'] ? clean($r['full_name']) : '<span class="text-muted">—</span>' ?></td>
        <td><?= $r['success'] ? '<span class="nm-badge nm-badge-online">OK</span>' : '<span class="nm-badge nm-badge-offline">FAIL</span>' ?></td>
        <td class="text-mono" style="font-size:.78rem"><?= clean($r['ip_address']) ?></td>
        <td style="font-size:.78rem"><i class="bi bi-<?= $r['device_type']==='mobile'?'phone':($r['device_type']==='tablet'?'tablet':'display') ?> me-1"></i><?= clean($r['device_type']) ?></td>
        <td style="font-size:.78rem"><?= clean($r['os']??'—') ?></td>
        <td style="font-size:.78rem"><?= clean($r['browser']??'—') ?></td>
        <td style="font-size:.78rem"><?= clean($r['country']??'—') ?></td>
        <td style="font-size:.78rem"><?= clean($r['city']??'—') ?></td>
        <td style="font-size:.78rem;max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"><?= clean($r['isp']??'—') ?></td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>

<?php elseif ($tab === 'users'): ?>
<div class="nm-card p-0">
  <div class="nm-card-header px-3 pt-3 pb-2">
    <span class="fw-500">Korisnici sistema</span>
    <span class="text-muted ms-2 small">— promena role odmah invalidira sesiju</span>
  </div>
  <div class="table-responsive">
    <table class="nm-table">
      <thead><tr><th>Ime i prezime</th><th>Email</th><th>Rola</th><th>Status</th><th>Poslednja prijava</th><th>Akcije</th></tr></thead>
      <tbody>
      <?php foreach ($users as $u): ?>
      <tr>
        <td class="fw-500"><?= clean($u['full_name']) ?></td>
        <td style="font-size:.82rem"><?= clean($u['email']) ?></td>
        <td><?= $u['role']==='admin'
          ? '<span class="nm-badge" style="background:rgba(188,140,255,.15);color:#bc8cff;border:1px solid rgba(188,140,255,.3)"><i class="bi bi-shield-fill me-1"></i>Admin</span>'
          : '<span class="nm-badge nm-badge-unknown"><i class="bi bi-person me-1"></i>User</span>' ?></td>
        <td><?= $u['is_active'] ? '<span class="nm-badge nm-badge-online">aktivan</span>' : '<span class="nm-badge nm-badge-offline">neaktivan</span>' ?></td>
        <td style="font-size:.78rem" class="text-muted"><?= $u['last_login'] ? date('d.m.Y H:i',strtotime($u['last_login'])) : 'nikad' ?></td>
        <td>
          <?php if ((int)$u['id'] !== current_user_id()): ?>
          <div class="d-flex gap-1 flex-wrap">
            <form method="POST" style="display:inline">
              <?= csrf_field() ?><input type="hidden" name="action" value="toggle"><input type="hidden" name="user_id" value="<?= $u['id'] ?>">
              <button type="submit" class="btn btn-nm-ghost btn-sm py-1 px-2" title="<?= $u['is_active']?'Deaktiviraj':'Aktiviraj' ?>">
                <i class="bi bi-<?= $u['is_active']?'person-slash':'person-check' ?>"></i>
              </button>
            </form>
            <?php if ($u['role']==='user'): ?>
            <form method="POST" style="display:inline" onsubmit="return confirm('Postaviti <?= clean($u['full_name']) ?> za admina?')">
              <?= csrf_field() ?><input type="hidden" name="action" value="make_admin"><input type="hidden" name="user_id" value="<?= $u['id'] ?>">
              <button type="submit" class="btn btn-nm-ghost btn-sm py-1 px-2" title="Postavi za admina" style="color:#bc8cff;border-color:rgba(188,140,255,.4)">
                <i class="bi bi-shield-plus"></i> Admin
              </button>
            </form>
            <?php else: ?>
            <form method="POST" style="display:inline" onsubmit="return confirm('Degradirati <?= clean($u['full_name']) ?> na User?')">
              <?= csrf_field() ?><input type="hidden" name="action" value="make_user"><input type="hidden" name="user_id" value="<?= $u['id'] ?>">
              <button type="submit" class="btn btn-nm-ghost btn-sm py-1 px-2" title="Degradiraj na User">
                <i class="bi bi-shield-minus"></i> User
              </button>
            </form>
            <?php endif; ?>
          </div>
          <?php else: ?><span class="text-muted small">vi</span><?php endif; ?>
        </td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>

<?php elseif ($tab === 'stats'): ?>
<div class="row g-3 mb-4">
  <?php foreach ([
    ['Provere danas',    $stats['checks_today'],                      'text-mono'],
    ['Provere (7 dana)', $stats['checks_week'],                       'text-mono'],
    ['Uspešnost (7d)',   ($stats['success_rate']??0).'%',             ($stats['success_rate']??0)>=95?'text-success':'text-danger'],
    ['Avg odgovor (7d)', ($stats['avg_rt']??0).' ms',                 'text-mono'],
  ] as [$l,$v,$c]): ?>
  <div class="col-6 col-md-3"><div class="stat-box"><div class="stat-val <?= $c ?>"><?= $v ?></div><div class="stat-lbl"><?= $l ?></div></div></div>
  <?php endforeach; ?>
</div>
<div class="row g-3 mb-4">
  <div class="col-md-4">
    <div class="nm-card">
      <div class="nm-card-header"><span class="fw-500">Uređaji</span></div>
      <?php foreach ($stats['devices'] as $d): ?>
      <div class="d-flex justify-content-between mb-2">
        <span class="text-muted small"><i class="bi bi-<?= $d['device_type']==='mobile'?'phone':($d['device_type']==='tablet'?'tablet':'display') ?> me-2"></i><?= clean($d['device_type']) ?></span>
        <span class="text-mono small"><?= $d['cnt'] ?></span>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
  <div class="col-md-8">
    <div class="nm-card">
      <div class="nm-card-header"><span class="fw-500">Top države</span></div>
      <?php foreach ($stats['top_countries'] as $c): ?>
      <div class="d-flex justify-content-between mb-1">
        <span class="text-muted small"><?= clean($c['country']) ?></span>
        <span class="text-mono small"><?= $c['cnt'] ?></span>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
</div>
<?php if (!empty($stats['email_failures'])): ?>
<div class="nm-card p-0">
  <div class="nm-card-header px-3 pt-3 pb-2"><span class="fw-500">Greške slanja emaila</span></div>
  <div class="table-responsive">
    <table class="nm-table">
      <thead><tr><th>Vreme</th><th>Korisnik</th><th>Poruka</th></tr></thead>
      <tbody>
      <?php foreach ($stats['email_failures'] as $ef): ?>
      <tr>
        <td class="text-mono" style="font-size:.78rem"><?= date('d.m.Y H:i',strtotime($ef['created_at'])) ?></td>
        <td style="font-size:.82rem"><?= clean($ef['full_name']??'—') ?></td>
        <td style="font-size:.78rem" class="text-danger"><?= clean($ef['message']) ?></td>
      </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>
<?php endif; ?>
<?php endif; ?>

<?php require __DIR__ . '/views/footer.php'; ?>
