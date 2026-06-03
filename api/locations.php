<?php
require_once __DIR__ . '/../includes/bootstrap.php';

header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS, PATCH');
header('Access-Control-Allow-Headers: Authorization, Content-Type, X-CSRF-Token');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

$uri    = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri    = rtrim($uri, '/');
$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'POST' && preg_match('#/api/auth/token$#', $uri)) {
    $body  = json_decode(file_get_contents('php://input'), true) ?? [];
    $email = filter_var($body['email'] ?? '', FILTER_SANITIZE_EMAIL);
    $pass  = $body['password'] ?? '';
    if (!$email || !$pass) json_die(400, 'email and password required.');
    $db   = Database::getInstance()->getConnection();
    $stmt = $db->prepare('SELECT id, email, password, full_name, role FROM users WHERE email = :email AND is_active = 1 LIMIT 1');
    $stmt->bindParam(':email', $email, PDO::PARAM_STR);
    $stmt->execute();
    $user = $stmt->fetch();
    if (!$user || !password_verify($pass, $user['password'])) json_die(401, 'Invalid credentials.');
    $token = jwt_encode(['sub' => $user['id'], 'name' => $user['full_name'], 'role' => $user['role']]);
    json_ok(['token' => $token, 'token_type' => 'Bearer', 'expires_in' => JWT_TTL,
             'user'  => ['id' => $user['id'], 'name' => $user['full_name'], 'role' => $user['role']]],
            'Token issued.');
}

if (!preg_match('#/api/locations(?:/(\d+)(?:/(check))?)?$#', $uri, $m)) json_die(404, 'Endpoint not found.');

$resourceId = isset($m[1]) ? (int)$m[1] : null;
$subAction  = $m[2] ?? null;
$payload    = require_api_auth();
$authUid    = (int)$payload['sub'];
$authRole   = $payload['role'] ?? 'user';
$db         = Database::getInstance()->getConnection();

if ($subAction === 'check') {
    if ($method !== 'POST') json_die(405, 'Method not allowed.');
    if (!$resourceId) json_die(400, 'Location ID required.');
    $stmt = $db->prepare('SELECT * FROM locations WHERE id = :id LIMIT 1');
    $stmt->bindParam(':id', $resourceId, PDO::PARAM_INT);
    $stmt->execute();
    $loc = $stmt->fetch();
    if (!$loc) json_die(404, 'Location not found.');
    $result = run_and_store_check($db, $loc);
    json_ok(['location_id' => $resourceId, 'success' => (bool)$result['success'],
             'response_time' => $result['response_time'], 'error_message' => $result['error_message'],
             'checked_at' => date('Y-m-d\TH:i:sP')],
            $result['success'] ? 'Host is reachable.' : 'Host is unreachable.');
}

match ([$method, $resourceId === null]) {
    ['GET', true]   => handle_list($db),
    ['POST', true]  => handle_create($db, $authUid, $authRole),
    ['GET', false]  => handle_get($db, $resourceId),
    ['PUT', false]  => handle_update($db, $resourceId, $authRole),
    ['PATCH', false] => handle_update($db, $resourceId, $authRole),
    ['DELETE',false]=> handle_delete($db, $resourceId, $authRole),
    default         => json_die(405, 'Method not allowed.'),
};

function handle_list(PDO $db): void {
    $page = max(1,(int)($_GET['page']??1));
    $per  = min(100,max(1,(int)($_GET['per_page']??20)));
    $off  = ($page-1)*$per;
    $total= (int)$db->query("SELECT COUNT(*) FROM locations")->fetchColumn();
    $locs = $db->query("SELECT * FROM locations ORDER BY created_at DESC LIMIT $per OFFSET $off")->fetchAll();
    json_ok(['locations'=>$locs,'pagination'=>['total'=>$total,'page'=>$page,'per_page'=>$per,'pages'=>ceil($total/$per)]]);
}
function handle_get(PDO $db, int $id): void {
    $stmt = $db->prepare('SELECT * FROM locations WHERE id = :id LIMIT 1');
    $stmt->bindParam(':id',$id,PDO::PARAM_INT); $stmt->execute();
    $loc = $stmt->fetch();
    if (!$loc) json_die(404,'Location not found.');
    $h = $db->prepare('SELECT success,response_time,error_message,checked_at FROM checks WHERE location_id=:id ORDER BY checked_at DESC LIMIT 10');
    $h->bindParam(':id',$id,PDO::PARAM_INT); $h->execute();
    $loc['recent_checks'] = $h->fetchAll();
    json_ok($loc);
}
function handle_create(PDO $db, int $uid, string $role): void {
    if ($role !== 'admin') json_die(403,'Only admins can create locations.');
    $body = json_decode(file_get_contents('php://input'),true);
    if (!$body) json_die(400,'Invalid JSON.');
    $name=$body['name']??''; $host=$body['host']??''; $port=(int)($body['port']??80);
    $proto=$body['protocol']??'tcp'; $desc=$body['description']??''; $active=(int)($body['is_active']??1);
    $errs=[];
    if (!$name||strlen($name)>100) $errs[]='name required';
//    if (!validate_hostname($host)&&!validate_ip($host)) $errs[]='invalid host';
//    if (is_private_ip($host)) $errs[]='private/reserved IP addresses not allowed';
    if (!validate_port($port)) $errs[]='invalid port';
    if (!in_array($proto,['tcp','http','https','icmp'],true)) $errs[]='invalid protocol';
    if ($errs) json_die(422,'Validation failed.',$errs);
    $stmt=$db->prepare('INSERT INTO locations (user_id,name,host,port,protocol,description,is_active) VALUES (:uid,:n,:h,:p,:pr,:d,:a)');
    $stmt->bindParam(':uid',$uid,PDO::PARAM_INT); $stmt->bindParam(':n',$name,PDO::PARAM_STR);
    $stmt->bindParam(':h',$host,PDO::PARAM_STR);  $stmt->bindParam(':p',$port,PDO::PARAM_INT);
    $stmt->bindParam(':pr',$proto,PDO::PARAM_STR); $stmt->bindParam(':d',$desc,PDO::PARAM_STR);
    $stmt->bindParam(':a',$active,PDO::PARAM_INT); $stmt->execute();
    $newId=(int)$db->lastInsertId();
    $s=$db->prepare('SELECT * FROM locations WHERE id=:id'); $s->bindParam(':id',$newId,PDO::PARAM_INT); $s->execute();
    json_ok($s->fetch(),'Location created.',201);
}
function handle_update(PDO $db, int $id, string $role): void {
    if ($role!=='admin') json_die(403,'Only admins can update locations.');
    $stmt=$db->prepare('SELECT * FROM locations WHERE id=:id LIMIT 1');
    $stmt->bindParam(':id',$id,PDO::PARAM_INT); $stmt->execute();
    $loc=$stmt->fetch(); if (!$loc) json_die(404,'Location not found.');
    $body=json_decode(file_get_contents('php://input'),true); if (!$body) json_die(400,'Invalid JSON.');
    $name=$body['name']??$loc['name']; $host=$body['host']??$loc['host'];
    $port=(int)($body['port']??$loc['port']); $proto=$body['protocol']??$loc['protocol'];
    $desc=$body['description']??$loc['description']; $active=isset($body['is_active'])?(int)$body['is_active']:$loc['is_active'];
//    if (!validate_hostname($host)&&!validate_ip($host)) $errs[]='invalid host';
//    if (is_private_ip($host)) $errs[]='private/reserved IP addresses not allowed';
    $stmt=$db->prepare('UPDATE locations SET name=:n,host=:h,port=:p,protocol=:pr,description=:d,is_active=:a WHERE id=:id');
    $stmt->bindParam(':n',$name,PDO::PARAM_STR); $stmt->bindParam(':h',$host,PDO::PARAM_STR);
    $stmt->bindParam(':p',$port,PDO::PARAM_INT); $stmt->bindParam(':pr',$proto,PDO::PARAM_STR);
    $stmt->bindParam(':d',$desc,PDO::PARAM_STR); $stmt->bindParam(':a',$active,PDO::PARAM_INT);
    $stmt->bindParam(':id',$id,PDO::PARAM_INT);  $stmt->execute();
    $s=$db->prepare('SELECT * FROM locations WHERE id=:id'); $s->bindParam(':id',$id,PDO::PARAM_INT); $s->execute();
    json_ok($s->fetch(),'Location updated.');

}
function handle_delete(PDO $db, int $id, string $role): void {
    if ($role!=='admin') json_die(403,'Only admins can delete locations.');
    $stmt=$db->prepare('SELECT id FROM locations WHERE id=:id LIMIT 1');
    $stmt->bindParam(':id',$id,PDO::PARAM_INT); $stmt->execute();
    if (!$stmt->fetch()) json_die(404,'Location not found.');
    $db->prepare('DELETE FROM locations WHERE id=:id')->execute([':id'=>$id]);
    json_ok(null,'Location deleted.');
}
