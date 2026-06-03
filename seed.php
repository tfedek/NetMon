<?php
/**
 * Database seeder
 *
 * Koristi Faker biblioteku (fakerphp/faker via Composer) ako je dostupna.
 * Ako nije, koristi vlastite helper funkcije kao adekvatnu zamenu.
 * Pokretanje: http://localhost/netmon_v4/seed.php
 */
require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/Database.php';

// Pokusaj ucitavanja Faker-a via Composer
$hasFaker = false;
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
    if (class_exists('Faker\Factory')) {
        $hasFaker = true;
    }
}

$isCli = php_sapi_name() === 'cli';
if (!$isCli) {
    echo '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>NetMon Seeder</title>
    <style>body{background:#0d1117;color:#e6edf3;font-family:monospace;padding:30px;}
    .ok{color:#3fb950;}.warn{color:#d29922;}.err{color:#f85149;}
    .hd{color:#58a6ff;font-size:1.2em;margin-bottom:10px;}a{color:#58a6ff;}
    </style></head><body><div class="hd">NetMon v4 – Database Seeder</div><pre>';
}

function out(string $msg, string $type = 'ok'): void {
    global $isCli;
    if ($isCli) echo $msg . "\n";
    else echo '<span class="' . $type . '">' . htmlspecialchars($msg) . '</span>' . "\n";
}

// ── Fallback helper funkcije (zamena za Faker) ─────────────────
function randIp(): string {
    return rand(1,254).'.'.rand(0,255).'.'.rand(0,255).'.'.rand(1,254);
}
function randOs(): string {
    $l = ['Ubuntu 22.04','Debian 12','Windows Server 2022','CentOS 7','Rocky Linux 9'];
    return $l[array_rand($l)];
}
function randBrowser(): string {
    $l = ['Chrome 122','Firefox 124','Edge 122','Safari 17'];
    return $l[array_rand($l)];
}
function randCity(): array {
    $data = [
        ['Novi Sad',    'Serbia',  'SBB'],
        ['Belgrade',    'Serbia',  'Telekom Srbija'],
        ['Nis',         'Serbia',  'Orion Telekom'],
        ['Subotica',    'Serbia',  'ITS'],
        ['Kragujevac',  'Serbia',  'A1 Srbija'],
        ['Zagreb',      'Croatia', 'HT Eronet'],
        ['Ljubljana',   'Slovenia','Telekom Slovenije'],
    ];
    return $data[array_rand($data)];
}

// ── Konekcija ─────────────────────────────────────────────────
try {
    $db = Database::getInstance()->getConnection();
    out("✓ Konektovan na bazu '" . DB_NAME . "'");
    if ($hasFaker) out("✓ Faker biblioteka dostupna (fakerphp/faker via Composer)");
    else out("~ Faker nije instaliran – koristim sopstvene helper funkcije kao zamenu", 'warn');
} catch (Exception $e) {
    out("✗ " . $e->getMessage(), 'err');
    if (!$isCli) echo '</pre></body></html>';
    exit;
}

// Faker instanca (ako je dostupna)
$faker = $hasFaker ? Faker\Factory::create('sr_Latn_RS') : null;

// ── Korisnici ─────────────────────────────────────────────────
out("\n── Kreiranje korisnika ──────────────────────────────");
$users = [
    ['admin@netmon.local',    'Admin1234!', 'System Administrator', 'admin'],
    ['jorleanka@example.com',    'Pass1234!',  'Jovanka Orleanka',           'user'],
    ['nemanjam@example.com',    'Pass1234!',  'Nemanja Matic',            'user'],
    ['bijelicka@example.com', 'Pass1234!',  'Natasa Bijelic',       'user'],
    ['tamdeyfantom@example.com',  'Pass1234!',  'Dejan Tamas',        'admin'],
];

// Ako ima Faker, dodaj jos random korisnika
if ($faker) {
    for ($i = 0; $i < 5; $i++) {
        $fn = $faker->firstName();
        $ln = $faker->lastName();
        $users[] = [
            strtolower($fn . '.' . $ln) . '@example.com',
            'Pass1234!',
            $fn . ' ' . $ln,
            'user'
        ];
    }
}

$userIds = [];
foreach ($users as $u) {
    $hash = password_hash($u[1], PASSWORD_BCRYPT, ['cost' => 12]);
    $stmt = $db->prepare("INSERT IGNORE INTO users (email, password, full_name, role) VALUES (:e, :p, :n, :r)");
    $stmt->bindParam(':e', $u[0], PDO::PARAM_STR);
    $stmt->bindParam(':p', $hash, PDO::PARAM_STR);
    $stmt->bindParam(':n', $u[2], PDO::PARAM_STR);
    $stmt->bindParam(':r', $u[3], PDO::PARAM_STR);
    $stmt->execute();
    $id = (int)$db->lastInsertId();
    if (!$id) {
        $r = $db->prepare("SELECT id FROM users WHERE email = :e");
        $r->bindParam(':e', $u[0], PDO::PARAM_STR);
        $r->execute();
        $row = $r->fetch();
        $id  = $row ? (int)$row['id'] : 0;
        out("  ~ '{$u[0]}' [{$u[3]}] već postoji → id $id");
    } else {
        out("  + '{$u[0]}' [{$u[3]}] kreiran → id $id");
    }
    if ($id) $userIds[] = $id;
}

// ── Lokacije ──────────────────────────────────────────────────
out("\n── Kreiranje lokacija ───────────────────────────────");
$adminId = $userIds[0];


$locationData = [
    ['VTŠ glavni sajt',        'vts.su.ac.rs',        443, 'https', 'online'],
    ['VTŠ HTTP redirect',      'vts.su.ac.rs',        80,  'http',  'online'],
    ['Moodle platforma',       'moodle2.vts.su.ac.rs',443, 'https', 'online'],
    ['Webmail',                'webmail.su.ac.rs',    443, 'https', 'unknown'],
    ['Mail SMTP',              'mail.su.ac.rs',       25,  'tcp',   'unknown'],

];



// Ako ima Faker, dodaj jos random lokacija
if ($faker) {
    for ($i = 0; $i < 5; $i++) {
        $locationData[] = [
            $faker->streetAddress(),
            $faker->localIpv4(),
            [80, 443, 22, 8080, 3306][array_rand([80, 443, 22, 8080, 3306])],
            ['tcp', 'http', 'https'][array_rand(['tcp', 'http', 'https'])],
            ['online', 'offline', 'unknown'][array_rand(['online', 'offline', 'unknown'])],
        ];
    }
}

foreach ($locationData as [$name, $host, $port, $proto, $status]) {
    $desc = "Monitoring node for $name";
    $stmt = $db->prepare(
        "INSERT IGNORE INTO locations (user_id, name, host, port, protocol, description, status, last_checked)
         VALUES (:u, :n, :h, :p, :pr, :d, :s, NOW())"
    );
    $stmt->bindParam(':u',  $adminId, PDO::PARAM_INT);
    $stmt->bindParam(':n',  $name,    PDO::PARAM_STR);
    $stmt->bindParam(':h',  $host,    PDO::PARAM_STR);
    $stmt->bindParam(':p',  $port,    PDO::PARAM_INT);
    $stmt->bindParam(':pr', $proto,   PDO::PARAM_STR);
    $stmt->bindParam(':d',  $desc,    PDO::PARAM_STR);
    $stmt->bindParam(':s',  $status,  PDO::PARAM_STR);
    $stmt->execute();
    $locId = (int)$db->lastInsertId();
    if (!$locId) { out("  ~ '$name' već postoji"); continue; }
    out("  + '$name' → id $locId ($host:$port)");

    // 48h istorija provera
    for ($h = 48; $h >= 0; $h--) {
        $ok  = rand(0,9) > 1 ? 1 : 0;
        $rt  = $ok ? round(mt_rand(2, 380) / 10, 1) : null;
        $err = $ok ? null : ['Connection refused','Timeout','Host unreachable'][rand(0,2)];
        $ts  = date('Y-m-d H:i:s', strtotime("-{$h} hours"));
        $db->prepare(
            "INSERT INTO checks (location_id, success, response_time, error_message, checked_at)
             VALUES (?, ?, ?, ?, ?)"
        )->execute([$locId, $ok, $rt, $err, $ts]);
    }
}

// ── Login audit ───────────────────────────────────────────────
out("\n── Kreiranje login audit zapisa ─────────────────────");
$agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122.0',
    'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Firefox/124.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) Safari/605.1.15',
];
$devTypes = ['desktop', 'mobile', 'tablet'];

for ($i = 0; $i < 30; $i++) {
    $uid = $userIds[array_rand($userIds)];
    $ts  = date('Y-m-d H:i:s', strtotime('-' . rand(0,72) . ' hours'));

    if ($faker) {
        $ip      = $faker->ipv4();
        $city    = $faker->city();
        $country = $faker->country();
        $isp     = $faker->company() . ' Telecom';
        $os      = randOs();
        $browser = randBrowser();
    } else {
        $ip      = randIp();
        $geo     = randCity();
        $city    = $geo[0]; $country = $geo[1]; $isp = $geo[2];
        $os      = randOs();
        $browser = randBrowser();
    }

    $agent = $agents[array_rand($agents)];
    $dev   = $devTypes[rand(0,2)];
    $ok    = rand(0,4) > 0 ? 1 : 0;
    $email = "user{$uid}@example.com";

    $db->prepare(
        "INSERT INTO login_audit
         (user_id, email, success, ip_address, user_agent, device_type, os, browser, country, city, isp, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
    )->execute([$uid, $email, $ok, $ip, $agent, $dev, $os, $browser, $country, $city, $isp, $ts]);
}
out("  + 30 audit zapisa kreirana");

// ── Gotovo ────────────────────────────────────────────────────
out("\n✓ Seeder završen uspešno!");
out("─────────────────────────────────────────────────────");
out("  Admin:  admin@netmon.local  / Admin1234!");
out("  Admin2: tamdeyfantom@example.com / Pass1234!");
out("  User:   bijelicka@example.com  / Pass1234!");
out("─────────────────────────────────────────────────────");
if ($faker) out("  (Podaci generisani uz pomoć Faker biblioteke)");
else out("  (Faker nije instaliran – koriscene su sopstvene helper funkcije)", 'warn');

if (!$isCli) {
    echo '</pre>';
    echo '<p style="margin-top:20px"><a href="/netmon_v4/login.php">→ Idi na Login</a></p>';
    echo '</body></html>';
}
