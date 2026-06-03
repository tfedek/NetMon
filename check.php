<?php
require_once __DIR__ . '/includes/bootstrap.php';
require_admin();

$db = Database::getInstance()->getConnection();
$id = (int)($_GET['id'] ?? 0);

if (!$id) { header('Location: ' . APP_URL . '/locations.php'); exit; }

$stmt = $db->prepare('SELECT * FROM locations WHERE id = :id LIMIT 1');
$stmt->bindParam(':id', $id, PDO::PARAM_INT);
$stmt->execute();
$loc = $stmt->fetch();

if (!$loc) { header('Location: ' . APP_URL . '/locations.php'); exit; }

run_and_store_check($db, $loc);
header('Location: ' . APP_URL . '/index.php');
exit;
