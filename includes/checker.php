<?php
function check_location(array $loc): array {
    $start   = microtime(true);
    $success = false;
    $error   = null;
    $host    = $loc['host'];
    $port    = (int)$loc['port'];

    if (!validate_hostname($host) && !validate_ip($host)) {
        return ['success' => false, 'response_time' => null, 'error_message' => 'Invalid host'];
    }

    switch ($loc['protocol']) {
        case 'http':
        case 'https':
            $url = $loc['protocol'] . '://' . $host . ':' . $port . '/';
            $ch  = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, CHECK_TIMEOUT);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, CHECK_TIMEOUT);
            curl_setopt($ch, CURLOPT_NOBODY, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
            curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $success  = ($httpCode > 0);
            if (!$success) $error = curl_error($ch) ?: 'HTTP request failed';
            curl_close($ch);
            break;

        case 'tcp':
        default:
            $fp = @fsockopen($host, $port, $errno, $errstr, CHECK_TIMEOUT);
            if ($fp) { fclose($fp); $success = true; }
            else $error = $errstr ?: "Connection refused (error $errno)";
            break;
    }

    $elapsed = round((microtime(true) - $start) * 1000, 1);
    return [
        'success'       => $success,
        'response_time' => $success ? $elapsed : null,
        'error_message' => $error,
    ];
}

function run_and_store_check(PDO $db, array $loc): array {
    $result = check_location($loc);

    $ok     = $result['success'] ? 1 : 0;
    $rt     = $result['response_time'];
    $err    = $result['error_message'];
    $locId  = $loc['id'];

    $stmt = $db->prepare(
        "INSERT INTO checks (location_id, success, response_time, error_message) VALUES (:lid, :ok, :rt, :err)"
    );
    $stmt->bindParam(':lid', $locId, PDO::PARAM_INT);
    $stmt->bindParam(':ok',  $ok,    PDO::PARAM_INT);
    $stmt->bindParam(':rt',  $rt);
    $stmt->bindParam(':err', $err,   PDO::PARAM_STR);
    $stmt->execute();

    $status = $result['success'] ? 'online' : 'offline';
    $stmt2  = $db->prepare("UPDATE locations SET status = :s, last_checked = NOW() WHERE id = :id");
    $stmt2->bindParam(':s',  $status, PDO::PARAM_STR);
    $stmt2->bindParam(':id', $locId,  PDO::PARAM_INT);
    $stmt2->execute();

    $result['location_id'] = $locId;
    return $result;
}
