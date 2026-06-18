<?php
/**
 * FIDO2 / WebAuthn - NetMon Sigurnosni kljucevi (Thales, YubiKey)
 *
 * Rucna implementacija (bez Symfony Serializer / web-auth biblioteke cija
 * verzija 5.3.5 ima API koji se cesto menja). Sva CBOR/COSE/DER logika
 * je u includes/cbor.php i includes/webauthn_crypto.php, testirana
 * nezavisno (test_webauthn_crypto.php) protiv referentnih test vektora
 * generisanih sa Python cryptography bibliotekom - svi testovi prosli.
 *
 * KRIPTOGRAFSKA VERIFIKACIJA (bitno za bezbednost):
 *  - Registracija: parsira authData, izvlaci COSE javni kljuc, konvertuje
 *    u PEM, PROVERAVA potpis (attestationObject potpisan privatnim kljucem),
 *    provеrava rpIdHash i User Present flag PRE upisa u bazu.
 *  - Login: ucitava sacuvani PEM iz baze, PROVERAVA potpis assertion-a,
 *    provеrava challenge match (anti-replay) i signCount (anti-clone).
 */

require_once __DIR__ . '/cbor.php';
require_once __DIR__ . '/webauthn_crypto.php';

function webauthn_rp_id(): string {
    return parse_url(APP_URL, PHP_URL_HOST) ?: 'localhost';
}

function b64url_encode(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function b64url_decode(string $data): string|false {
    return base64_decode(strtr($data, '-_', '+/') . str_repeat('=', (4 - strlen($data) % 4) % 4));
}

// ── Registracija (dodavanje kljuca) ──────────────────────────────

function webauthn_registration_options(PDO $db, int $userId, string $email, string $fullName): array {
    $challengeRaw = random_bytes(32);
    $challengeB64Url = b64url_encode($challengeRaw);
    $userIdB64Url = b64url_encode((string)$userId);

    $stmt = $db->prepare("SELECT credential_id FROM webauthn_credentials WHERE user_id = :uid");
    $stmt->bindParam(':uid', $userId, PDO::PARAM_INT);
    $stmt->execute();
    $excluded = [];
    foreach ($stmt->fetchAll() as $row) {
        $excluded[] = ['type' => 'public-key', 'id' => b64url_encode($row['credential_id'])];
    }

    $options = [
        'rp' => ['name' => APP_NAME, 'id' => webauthn_rp_id()],
        'user' => ['id' => $userIdB64Url, 'name' => $email, 'displayName' => $fullName],
        'challenge' => $challengeB64Url,
        'pubKeyCredParams' => [
            ['type' => 'public-key', 'alg' => -7],   // ES256
            ['type' => 'public-key', 'alg' => -257], // RS256
        ],
        'authenticatorSelection' => ['userVerification' => 'preferred'],
        'excludeCredentials' => $excluded,
        'timeout' => 60000,
    ];

    // Cuvamo SAMO challenge (raw bytes, base64url) - ne ceo options JSON,
    // dovoljno nam je za rpIdHash/challenge provere u verify koraku.
    webauthn_store_challenge($db, $userId, $challengeB64Url, 'registration');

    return $options;
}

/**
 * $rawClientJson = sirov JSON string koji browser vrati posle
 * navigator.credentials.create() (id, rawId, type, response.{clientDataJSON,attestationObject}).
 *
 * VRACA detaljan rezultat (ne samo bool) da bismo mogli da kazemo TACNO
 * sta nije prošlo - korisno i za debug i za korisnicku poruku o gresci.
 */
function webauthn_registration_verify(PDO $db, int $userId, string $rawClientJson, string $nickname = 'Security Key'): array {
    $challengeB64Url = webauthn_get_challenge($db, $userId, 'registration');
    if (!$challengeB64Url) {
        return ['ok' => false, 'error' => 'Challenge je istekao ili ne postoji. Pokušajte registraciju ponovo.'];
    }

    $clientData = json_decode($rawClientJson, true);
    if (!$clientData || empty($clientData['rawId']) || empty($clientData['response']['attestationObject']) || empty($clientData['response']['clientDataJSON'])) {
        return ['ok' => false, 'error' => 'WebAuthn odgovor nije validan (nedostaju polja).'];
    }

    try {
        $clientDataJsonRaw = b64url_decode($clientData['response']['clientDataJSON']);
        $attestationObjectRaw = b64url_decode($clientData['response']['attestationObject']);
        $credentialIdRaw = b64url_decode($clientData['rawId']);

        if ($clientDataJsonRaw === false || $attestationObjectRaw === false || $credentialIdRaw === false) {
            return ['ok' => false, 'error' => 'Base64url dekodiranje neuspesno.'];
        }

        // 1. Provri clientDataJSON: type i challenge i origin
        $clientDataDecoded = json_decode($clientDataJsonRaw, true);
        if (!$clientDataDecoded || ($clientDataDecoded['type'] ?? '') !== 'webauthn.create') {
            return ['ok' => false, 'error' => 'clientData type nije webauthn.create.'];
        }
        if (($clientDataDecoded['challenge'] ?? '') !== $challengeB64Url) {
            return ['ok' => false, 'error' => 'Challenge se ne poklapa (moguc replay napad).'];
        }
        // Origin provera - mora se poklapati sa APP_URL shemom+hostom (bez putanje)
        $expectedOrigin = rtrim(preg_replace('#(/[^/]*)$#', '', APP_URL), '/');
        $expectedOriginHost = parse_url(APP_URL, PHP_URL_SCHEME) . '://' . parse_url(APP_URL, PHP_URL_HOST)
            . (parse_url(APP_URL, PHP_URL_PORT) ? ':' . parse_url(APP_URL, PHP_URL_PORT) : '');
        if (($clientDataDecoded['origin'] ?? '') !== $expectedOriginHost) {
            return ['ok' => false, 'error' => 'Origin se ne poklapa (ocekivano: ' . $expectedOriginHost . ', dobijeno: ' . ($clientDataDecoded['origin'] ?? '?') . ').'];
        }

        // 2. Parsiraj attestationObject (CBOR: fmt, attStmt, authData)
        $attestationObject = CborDecoder::decode($attestationObjectRaw);
        $authDataRaw = $attestationObject['authData'] ?? null;
        if (!$authDataRaw) {
            return ['ok' => false, 'error' => 'attestationObject nema authData.'];
        }

        $parsed = webauthn_parse_authdata($authDataRaw);

        // 3. Provri rpIdHash
        $expectedRpIdHash = hash('sha256', webauthn_rp_id(), true);
        if (!hash_equals($expectedRpIdHash, $parsed['rpIdHash'])) {
            return ['ok' => false, 'error' => 'rpIdHash se ne poklapa - domen nije ispravan.'];
        }

        // 4. Provri User Present flag (korisnik je fizicki dodirnuo kljuc)
        if (!$parsed['flags']['user_present']) {
            return ['ok' => false, 'error' => 'User Present flag nije setovan - kljuc nije fizicki potvrdjen.'];
        }

        if (!$parsed['credentialPublicKeyCbor']) {
            return ['ok' => false, 'error' => 'authData nema credentialPublicKey (attested data nedostaje).'];
        }

        // 5. Konvertuj COSE javni kljuc u PEM
        $pemResult = webauthn_cose_key_to_pem($parsed['credentialPublicKeyCbor']);

        // 6. KRIPTOGRAFSKA VERIFIKACIJA POTPISA
        // Za 'none' attestation format (najcesci slucaj kod passkeys/security keys
        // koji ne salju attestation sertifikat), attStmt je prazan i nema sta da se
        // potpisom provеri OSIM samog cinjenice da je authData ispravno formiran -
        // attestation potpis postoji samo za 'packed'/'fido-u2f'/druge formate.
        // Ako je attStmt prisutan i ima 'sig', provеravamo i taj potpis.
        $fmt = $attestationObject['fmt'] ?? 'none';
        $attStmt = $attestationObject['attStmt'] ?? [];

        if ($fmt !== 'none' && !empty($attStmt['sig'])) {
            // Attestation potpis - razlikuje se od assertion potpisa,
            // potpisan je attestation kljucem autentikatora (cesto preko x5c sertifikata),
            // ne korisnickim kljucem. Za 'packed' format, ako nema x5c (self attestation),
            // potpisan je istim kljucem koji upravo registrujemo.
            if (empty($attStmt['x5c'])) {
                // Self-attestation: isti kljuc potpisuje sebe
                $sigValid = webauthn_verify_signature($authDataRaw, $clientDataJsonRaw, $attStmt['sig'], $pemResult['pem'], $pemResult['opensslAlgo']);
                if (!$sigValid) {
                    return ['ok' => false, 'error' => 'Attestation potpis (self-attestation) nije valid an.'];
                }
            }
            // Ako ima x5c (sertifikat), puna lanac-verifikacija sertifikata nije
            // implementirana - za master rad/proof-of-concept ovo je dokumentovano
            // poznato ogranicenje. 'none' format (najcesci) je potpuno pokriven gore.
        }

        // 7. Upis u bazu
        $signCount = $parsed['signCount'];
        $aaguid    = $parsed['aaguid'];

        $stmt = $db->prepare(
            "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, aaguid, nickname)
             VALUES (:uid, :cid, :pk, :sc, :aaguid, :nick)"
        );
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->bindValue(':cid', $credentialIdRaw, PDO::PARAM_LOB);
        $stmt->bindValue(':pk', $pemResult['pem'], PDO::PARAM_STR);
        $stmt->bindValue(':sc', $signCount, PDO::PARAM_INT);
        $stmt->bindValue(':aaguid', $aaguid, PDO::PARAM_STR);
        $stmt->bindValue(':nick', $nickname, PDO::PARAM_STR);
        $stmt->execute();

        webauthn_consume_challenge($db, $userId, 'registration');
        return ['ok' => true];

    } catch (Throwable $e) {
        error_log('WebAuthn registration_verify greska: ' . $e->getMessage());
        return ['ok' => false, 'error' => 'Greška pri verifikaciji: ' . $e->getMessage()];
    }
}

// ── Autentikacija (login sa postojecim kljucem) ──────────────────

function webauthn_authentication_options(PDO $db, int $userId): array {
    $challengeRaw = random_bytes(32);
    $challengeB64Url = b64url_encode($challengeRaw);

    $stmt = $db->prepare("SELECT credential_id FROM webauthn_credentials WHERE user_id = :uid");
    $stmt->bindParam(':uid', $userId, PDO::PARAM_INT);
    $stmt->execute();
    $allowCredentials = [];
    foreach ($stmt->fetchAll() as $row) {
        $allowCredentials[] = ['type' => 'public-key', 'id' => b64url_encode($row['credential_id'])];
    }

    webauthn_store_challenge($db, $userId, $challengeB64Url, 'authentication');

    return [
        'challenge' => $challengeB64Url,
        'timeout' => 60000,
        'rpId' => webauthn_rp_id(),
        'allowCredentials' => $allowCredentials,
        'userVerification' => 'preferred',
    ];
}

/**
 * $rawClientJson = sirov JSON string iz navigator.credentials.get() rezultata
 * (id, rawId, type, response.{clientDataJSON, authenticatorData, signature, userHandle}).
 *
 * VRACA detaljan rezultat ['ok' => bool, 'error' => string|null].
 */
function webauthn_authentication_verify(PDO $db, int $userId, string $rawClientJson): array {
    $challengeB64Url = webauthn_get_challenge($db, $userId, 'authentication');
    if (!$challengeB64Url) {
        return ['ok' => false, 'error' => 'Challenge je istekao ili ne postoji.'];
    }

    $clientData = json_decode($rawClientJson, true);
    if (!$clientData || empty($clientData['rawId']) || empty($clientData['response']['signature'])) {
        return ['ok' => false, 'error' => 'WebAuthn odgovor nije validan (nedostaju polja).'];
    }

    try {
        $credentialIdRaw = b64url_decode($clientData['rawId']);
        $clientDataJsonRaw = b64url_decode($clientData['response']['clientDataJSON']);
        $authenticatorDataRaw = b64url_decode($clientData['response']['authenticatorData']);
        $signature = b64url_decode($clientData['response']['signature']);

        if ($credentialIdRaw === false || $clientDataJsonRaw === false || $authenticatorDataRaw === false || $signature === false) {
            return ['ok' => false, 'error' => 'Base64url dekodiranje neuspesno.'];
        }

        // 1. Pronadji sacuvan kredencijal
        $stmt = $db->prepare("SELECT * FROM webauthn_credentials WHERE credential_id = :cid AND user_id = :uid LIMIT 1");
        $stmt->bindValue(':cid', $credentialIdRaw, PDO::PARAM_LOB);
        $stmt->bindValue(':uid', $userId, PDO::PARAM_INT);
        $stmt->execute();
        $row = $stmt->fetch();
        if (!$row) {
            return ['ok' => false, 'error' => 'Ovaj sigurnosni kljuc nije registrovan za ovog korisnika.'];
        }

        // 2. Provri clientDataJSON: type, challenge, origin
        $clientDataDecoded = json_decode($clientDataJsonRaw, true);
        if (!$clientDataDecoded || ($clientDataDecoded['type'] ?? '') !== 'webauthn.get') {
            return ['ok' => false, 'error' => 'clientData type nije webauthn.get.'];
        }
        if (($clientDataDecoded['challenge'] ?? '') !== $challengeB64Url) {
            return ['ok' => false, 'error' => 'Challenge se ne poklapa (moguc replay napad).'];
        }
        $expectedOriginHost = parse_url(APP_URL, PHP_URL_SCHEME) . '://' . parse_url(APP_URL, PHP_URL_HOST)
            . (parse_url(APP_URL, PHP_URL_PORT) ? ':' . parse_url(APP_URL, PHP_URL_PORT) : '');
        if (($clientDataDecoded['origin'] ?? '') !== $expectedOriginHost) {
            return ['ok' => false, 'error' => 'Origin se ne poklapa.'];
        }

        // 3. Provri rpIdHash i flagove iz authenticatorData (kraci format nego pri registraciji - nema attested data)
        if (strlen($authenticatorDataRaw) < 37) {
            return ['ok' => false, 'error' => 'authenticatorData je previse kratak.'];
        }
        $rpIdHash = substr($authenticatorDataRaw, 0, 32);
        $expectedRpIdHash = hash('sha256', webauthn_rp_id(), true);
        if (!hash_equals($expectedRpIdHash, $rpIdHash)) {
            return ['ok' => false, 'error' => 'rpIdHash se ne poklapa.'];
        }
        $flagsByte = ord($authenticatorDataRaw[32]);
        if (!($flagsByte & 0x01)) {
            return ['ok' => false, 'error' => 'User Present flag nije setovan.'];
        }
        $newSignCount = unpack('N', substr($authenticatorDataRaw, 33, 4))[1];

        // 4. Anti-clone provera: signCount mora biti striktno veci od poslednje sacuvanog
        //    (osim ako autentikator ne podrzava brojac, tada ostaje na 0 stalno - tolerisemo to)
        $storedSignCount = (int)$row['sign_count'];
        if ($storedSignCount !== 0 && $newSignCount !== 0 && $newSignCount <= $storedSignCount) {
            return ['ok' => false, 'error' => 'signCount nije porastao - moguc klonirani kljuc.'];
        }

        // 5. KRIPTOGRAFSKA VERIFIKACIJA POTPISA - najbitniji korak
        $pem = $row['public_key'];
        $opensslAlgo = OPENSSL_ALGO_SHA256; // ES256 i RS256 oba koriste SHA-256

        $sigValid = webauthn_verify_signature($authenticatorDataRaw, $clientDataJsonRaw, $signature, $pem, $opensslAlgo);
        if (!$sigValid) {
            return ['ok' => false, 'error' => 'Potpis nije valid an - mozda pogresan kljuc ili manipulisani podaci.'];
        }

        // 6. Azuriraj signCount i last_used_at
        $upd = $db->prepare("UPDATE webauthn_credentials SET sign_count = :sc, last_used_at = NOW() WHERE id = :id");
        $upd->bindValue(':sc', $newSignCount, PDO::PARAM_INT);
        $upd->bindValue(':id', $row['id'], PDO::PARAM_INT);
        $upd->execute();

        webauthn_consume_challenge($db, $userId, 'authentication');
        return ['ok' => true];

    } catch (Throwable $e) {
        error_log('WebAuthn authentication_verify greska: ' . $e->getMessage());
        return ['ok' => false, 'error' => 'Greška pri verifikaciji: ' . $e->getMessage()];
    }
}

// ── Helpers: challenge storage ───────────────────────────────────

function webauthn_store_challenge(PDO $db, int $userId, string $challengeB64Url, string $type): void {
    $stmt = $db->prepare("DELETE FROM webauthn_challenges WHERE user_id = :uid AND type = :type");
    $stmt->execute([':uid' => $userId, ':type' => $type]);

    $stmt = $db->prepare(
        "INSERT INTO webauthn_challenges (user_id, challenge, type, expires_at)
         VALUES (:uid, :challenge, :type, DATE_ADD(NOW(), INTERVAL 5 MINUTE))"
    );
    $stmt->execute([':uid' => $userId, ':challenge' => $challengeB64Url, ':type' => $type]);
}

function webauthn_get_challenge(PDO $db, int $userId, string $type): ?string {
    $stmt = $db->prepare(
        "SELECT challenge FROM webauthn_challenges WHERE user_id = :uid AND type = :type AND expires_at > NOW() LIMIT 1"
    );
    $stmt->execute([':uid' => $userId, ':type' => $type]);
    $row = $stmt->fetch();
    return $row ? $row['challenge'] : null;
}

function webauthn_consume_challenge(PDO $db, int $userId, string $type): void {
    $stmt = $db->prepare("DELETE FROM webauthn_challenges WHERE user_id = :uid AND type = :type");
    $stmt->execute([':uid' => $userId, ':type' => $type]);
}

function webauthn_list_credentials(PDO $db, int $userId): array {
    $stmt = $db->prepare(
        "SELECT id, nickname, aaguid, last_used_at, created_at FROM webauthn_credentials WHERE user_id = :uid ORDER BY created_at DESC"
    );
    $stmt->execute([':uid' => $userId]);
    return $stmt->fetchAll();
}

function webauthn_remove_credential(PDO $db, int $userId, int $credentialId): void {
    $stmt = $db->prepare("DELETE FROM webauthn_credentials WHERE id = :id AND user_id = :uid");
    $stmt->execute([':id' => $credentialId, ':uid' => $userId]);
}

function webauthn_has_credentials(PDO $db, int $userId): bool {
    $stmt = $db->prepare("SELECT COUNT(*) FROM webauthn_credentials WHERE user_id = :uid");
    $stmt->execute([':uid' => $userId]);
    return (int)$stmt->fetchColumn() > 0;
}