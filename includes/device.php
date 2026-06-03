<?php
/**
 * Detekcija uredjaja i IP geolokacija
 *
 * Koristi Mobile_Detect klasu (mobiledetect/mobiledetectlib via Composer).
 * Geo API se poziva cURL-om.
 */

// Ucitaj Composer autoload ako postoji, inace ucitaj manuelno
if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
    require_once __DIR__ . '/../vendor/autoload.php';
} else {
    require_once __DIR__ . '/MobileDetect/Mobile_Detect.php';
}

/**
 * Detektuje tip uredjaja, OS i browser iz User-Agent stringa.
 * Koristi Mobile_Detect klasu
 */
function detect_device(string $ua = ''): array {
    if (!$ua) $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

    // Mobile_Detect – originalna klasa (Composer: mobiledetect/mobiledetectlib)
    $detect = new Mobile_Detect(null, $ua); //ua je useragent koji dolazi iz Browser

    if ($detect->isTablet()) {
        $type = 'tablet';
    } elseif ($detect->isMobile()) {
        $type = 'mobile';
    } else {
        $type = 'desktop';
    }

    // OS detekcija
    $os = 'Unknown';
    $os_patterns = [
        '/windows nt 10/i'      => 'Windows 10/11',
        '/windows nt 6\.3/i'    => 'Windows 8.1',
        '/windows nt 6\.1/i'    => 'Windows 7',
        '/mac os x/i'           => 'macOS',
        '/android ([\d.]+)/i'   => 'Android $1',
        '/iphone os ([\d_]+)/i' => 'iOS',
        '/ubuntu/i'             => 'Ubuntu',
        '/linux/i'              => 'Linux',
    ];
    foreach ($os_patterns as $pattern => $name) {
        if (preg_match($pattern, $ua, $m)) {
            $os = isset($m[1]) ? str_replace('$1', str_replace('_','.',$m[1]), $name) : $name;
            break;
        }
    }

    // Browser detekcija
    $browser = 'Unknown';
    $b_patterns = [
        '/edg\//i'          => 'Edge',
        '/opr\//i'          => 'Opera',
        '/chrome\/(\d+)/i'  => 'Chrome $1',
        '/firefox\/(\d+)/i' => 'Firefox $1',
        '/safari\//i'       => 'Safari',
        '/msie|trident/i'   => 'Internet Explorer',
    ];
    foreach ($b_patterns as $pattern => $name) {
        if (preg_match($pattern, $ua, $m)) {
            $browser = isset($m[1]) ? str_replace('$1', $m[1], $name) : $name;
            break;
        }
    }

    return compact('type', 'os', 'browser', 'ua');
}

/**
 * Dohvata IP adresu klijenta.
 * Proverava proxy headere
 */
function get_client_ip(): string {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0]);
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'unknown';
}

/**
 * Poziva geo API korisćenjem cURL.

 */
function get_geo_data(string $ip): array {
    if ($ip === '127.0.0.1' || $ip === 'unknown'
        || str_starts_with($ip, '10.')
        || str_starts_with($ip, '192.168.')
        || str_starts_with($ip, '172.')) {
        return ['country' => 'Local', 'city' => 'Local', 'isp' => 'Local Network', 'raw' => '{}'];
    }

    $url = str_replace('{ip}', urlencode($ip), GEO_API_URL);

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    $raw = curl_exec($ch);
    curl_close($ch);

    if (!$raw) return ['country' => '', 'city' => '', 'isp' => '', 'raw' => '{}'];

    $data = json_decode($raw, true) ?? [];
    return [
        'country' => $data['country'] ?? '',
        'city'    => $data['city']    ?? '',
        'isp'     => $data['isp']     ?? $data['org'] ?? '',
        'raw'     => $raw,
    ];
}

/**
 * Upisuje login u audit tabelu.
 */
function log_access(PDO $db, ?int $userId, string $email, bool $success): void {
    $ip  = get_client_ip();
    $ua  = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $dev = detect_device($ua);
    $geo = get_geo_data($ip);

    $stmt = $db->prepare(
        "INSERT INTO login_audit
         (user_id, email, success, ip_address, user_agent, device_type, os, browser, country, city, isp, geo_raw)
         VALUES (:uid, :email, :ok, :ip, :ua, :dev, :os, :browser, :country, :city, :isp, :raw)"
    );
    $stmt->bindParam(':uid',     $userId,         PDO::PARAM_INT);
    $stmt->bindParam(':email',   $email,          PDO::PARAM_STR);
    $stmt->bindValue(':ok',      $success ? 1 : 0, PDO::PARAM_INT);
    $stmt->bindParam(':ip',      $ip,             PDO::PARAM_STR);
    $stmt->bindParam(':ua',      $ua,             PDO::PARAM_STR);
    $stmt->bindParam(':dev',     $dev['type'],    PDO::PARAM_STR);
    $stmt->bindParam(':os',      $dev['os'],      PDO::PARAM_STR);
    $stmt->bindParam(':browser', $dev['browser'], PDO::PARAM_STR);
    $stmt->bindParam(':country', $geo['country'], PDO::PARAM_STR);
    $stmt->bindParam(':city',    $geo['city'],    PDO::PARAM_STR);
    $stmt->bindParam(':isp',     $geo['isp'],     PDO::PARAM_STR);
    $stmt->bindParam(':raw',     $geo['raw'],     PDO::PARAM_STR);
    $stmt->execute();
}

/**
 * Loguje neuspelo slanje emaila u bazu.

 */
function log_email_failure(PDO $db, ?int $userId, string $message): void {
    $stmt = $db->prepare(
        "INSERT INTO email_failures (user_id, message) VALUES (:uid, :msg)"
    );
    $stmt->bindParam(':uid', $userId,  PDO::PARAM_INT);
    $stmt->bindParam(':msg', $message, PDO::PARAM_STR);
    $stmt->execute();
}
