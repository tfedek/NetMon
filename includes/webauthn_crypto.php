<?php

/**
 * webauthn_crypto.php - Parsiranje authData + COSE->PEM konverzija + potpis verifikacija
 *
 * Sve na osnovu W3C WebAuthn Level 2/3 spec i Copenhagen Book referenci.
 * Namerno bez spoljnih biblioteka (osim ugradjenog OpenSSL ekstenzije u PHP-u)
 * - svrha je da se razume i kontroliše tacno svaki korak verifikacije,
 * sto je i akademski vredniji prikaz za master rad.
 */

require_once __DIR__ . '/cbor.php';

/**
 * Parsira authenticatorData binarnu strukturu (RFC/W3C WebAuthn spec):
 *
 *   [0:32]   rpIdHash       - SHA-256 hash RP ID-a (npr. "localhost")
 *   [32]     flags          - 1 bajt bitflag-ova
 *   [33:37]  signCount      - 4 bajta, big-endian uint32
 *   [37:53]  aaguid         - 16 bajta (SAMO ako je attestedCredentialData prisutan, tj. flag bit 6 = 1)
 *   [53:55]  credIdLength   - 2 bajta, big-endian uint16
 *   [55:55+L] credentialId  - L bajtova
 *   [55+L:]  credentialPublicKey - CBOR/COSE struktura (samo pri registraciji)
 *
 * Flags bitovi (bit 0 = LSB):
 *   bit 0 (0x01) - UP  (User Present)
 *   bit 2 (0x04) - UV  (User Verified)
 *   bit 6 (0x40) - AT  (Attested credential data included - samo pri registraciji)
 *   bit 7 (0x80) - ED  (Extension data included)
 */
function webauthn_parse_authdata(string $authData): array
{
    if (strlen($authData) < 37) {
        throw new RuntimeException('authData je previse kratak (manje od 37 bajtova)');
    }

    $rpIdHash = substr($authData, 0, 32);
    $flagsByte = ord($authData[32]);
    $signCount = unpack('N', substr($authData, 33, 4))[1]; // big-endian uint32

    $flags = [
        'user_present' => (bool)($flagsByte & 0x01),
        'user_verified' => (bool)($flagsByte & 0x04),
        'attested_data' => (bool)($flagsByte & 0x40),
        'extension_data' => (bool)($flagsByte & 0x80),
    ];

    $result = [
        'rpIdHash' => $rpIdHash,
        'flags' => $flags,
        'signCount' => $signCount,
        'aaguid' => null,
        'credentialId' => null,
        'credentialPublicKeyCbor' => null,
    ];

    $offset = 37;

    if ($flags['attested_data']) {
        if (strlen($authData) < $offset + 16 + 2) {
            throw new RuntimeException('authData: nedostaju AAGUID/credentialIdLength bajtovi');
        }

        $aaguidRaw = substr($authData, $offset, 16);
        $offset += 16;

        $credIdLen = unpack('n', substr($authData, $offset, 2))[1]; // big-endian uint16
        $offset += 2;

        if (strlen($authData) < $offset + $credIdLen) {
            throw new RuntimeException('authData: credentialId duzina prelazi dostupne bajtove');
        }

        $credentialId = substr($authData, $offset, $credIdLen);
        $offset += $credIdLen;

        // Ostatak (od offset do kraja) je CBOR-enkodiran COSE javni kljuc.
        // Moze biti propracen extension podacima, pa koristimo decodeWithOffset
        // da znamo gde se CBOR struktura tacno zavrsila.
        $remaining = substr($authData, $offset);
        [$publicKeyCose, $consumedOffset] = CborDecoder::decodeWithOffset($remaining);

        $result['aaguid'] = webauthn_format_aaguid($aaguidRaw);
        $result['credentialId'] = $credentialId;
        $result['credentialPublicKeyCbor'] = $publicKeyCose;
    }

    return $result;
}

function webauthn_format_aaguid(string $raw16Bytes): string
{
    $hex = bin2hex($raw16Bytes);
    return sprintf(
        '%s-%s-%s-%s-%s',
        substr($hex, 0, 8),
        substr($hex, 8, 4),
        substr($hex, 12, 4),
        substr($hex, 16, 4),
        substr($hex, 20, 12)
    );
}

/**
 * Konvertuje COSE javni kljuc (dekodiran iz CBOR, kao asocijativni niz sa
 * integer kljucevima 1,3,-1,-2,-3...) u PEM format koji openssl_* funkcije
 * razumeju direktno.
 *
 * Podrzano:
 *  - EC2 (kty=2) sa ES256 (alg=-7), kriva P-256 (crv=1)
 *  - RSA (kty=3) sa RS256 (alg=-257)
 *
 * COSE Key Common Parameters: 1=kty, 3=alg
 * COSE EC2 Key Parameters:    -1=crv, -2=x, -3=y
 * COSE RSA Key Parameters:    -1=n (modulus), -2=e (exponent)
 */
function webauthn_cose_key_to_pem(array $coseKey): array
{
    $kty = $coseKey[1] ?? null;
    $alg = $coseKey[3] ?? null;

    if ($kty === 2) {
        // EC2 - eliptička kriva
        $crv = $coseKey[-1] ?? null;
        $x = $coseKey[-2] ?? null;
        $y = $coseKey[-3] ?? null;

        if ($crv !== 1) {
            throw new RuntimeException("Nepodrzana EC kriva (crv=$crv) - ocekivana P-256 (crv=1)");
        }
        if (!$x || !$y) {
            throw new RuntimeException('COSE EC2 kljuc nema x/y koordinate');
        }

        $pem = webauthn_ec_p256_to_pem($x, $y);
        return ['pem' => $pem, 'alg' => 'ES256', 'opensslAlgo' => OPENSSL_ALGO_SHA256];
    }

    if ($kty === 3) {
        // RSA
        $n = $coseKey[-1] ?? null;
        $e = $coseKey[-2] ?? null;

        if (!$n || !$e) {
            throw new RuntimeException('COSE RSA kljuc nema n/e komponente');
        }

        $pem = webauthn_rsa_to_pem($n, $e);
        return ['pem' => $pem, 'alg' => 'RS256', 'opensslAlgo' => OPENSSL_ALGO_SHA256];
    }

    throw new RuntimeException("Nepodrzan COSE key type (kty=$kty)");
}

/**
 * Pravi DER/PEM enkodiran EC P-256 javni kljuc iz sirovih x/y koordinata (32 bajta svaka).
 * Format: SubjectPublicKeyInfo sa unencoded point (0x04 || x || y), standardni
 * "uncompressed point" format definisan u SEC1.
 */
function webauthn_ec_p256_to_pem(string $x, string $y): string
{
    if (strlen($x) !== 32 || strlen($y) !== 32) {
        throw new RuntimeException('EC P-256 x/y koordinate moraju biti tacno 32 bajta');
    }

    // OID za id-ecPublicKey (1.2.840.10045.2.1) i prime256v1/secp256r1 (1.2.840.10045.3.1.7)
    $ecPublicKeyOid = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
    $prime256v1Oid = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";

    $algorithmSeq = der_sequence($ecPublicKeyOid . $prime256v1Oid);

    $uncompressedPoint = "\x04" . $x . $y; // 0x04 prefix = uncompressed point
    $publicKeyBitString = der_bit_string($uncompressedPoint);

    $spki = der_sequence($algorithmSeq . $publicKeyBitString);

    return wrap_pem($spki, 'PUBLIC KEY');
}

/**
 * Pravi DER/PEM enkodiran RSA javni kljuc iz sirovog modulusa (n) i exponenta (e).
 */
function webauthn_rsa_to_pem(string $n, string $e): string
{
    $rsaPublicKeyOid = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"; // rsaEncryption OID
    $nullParams = "\x05\x00";

    $algorithmSeq = der_sequence($rsaPublicKeyOid . $nullParams);

    $modulusInt = der_integer($n);
    $exponentInt = der_integer($e);
    $rsaKeySeq = der_sequence($modulusInt . $exponentInt);
    $rsaKeyBitString = der_bit_string($rsaKeySeq);

    $spki = der_sequence($algorithmSeq . $rsaKeyBitString);

    return wrap_pem($spki, 'PUBLIC KEY');
}

// ── Minimalni DER encoding helperi ──────────────────────────────

function der_length(int $len): string
{
    if ($len < 128) {
        return chr($len);
    }
    $bytes = '';
    while ($len > 0) {
        $bytes = chr($len & 0xFF) . $bytes;
        $len >>= 8;
    }
    return chr(0x80 | strlen($bytes)) . $bytes;
}

function der_sequence(string $content): string
{
    return "\x30" . der_length(strlen($content)) . $content;
}

function der_bit_string(string $content): string
{
    // Prvi bajt = broj "unused bits" na kraju (uvek 0 za nas slucaj, ceo broj bajtova)
    $body = "\x00" . $content;
    return "\x03" . der_length(strlen($body)) . $body;
}

function der_integer(string $bytes): string
{
    // DER INTEGER mora imati leading 0x00 ako je najznacajniji bit setovan
    // (da se ne protumaci kao negativan broj).
    if (strlen($bytes) > 0 && (ord($bytes[0]) & 0x80)) {
        $bytes = "\x00" . $bytes;
    }
    return "\x02" . der_length(strlen($bytes)) . $bytes;
}

function wrap_pem(string $der, string $label): string
{
    $base64 = base64_encode($der);
    $lines = trim(chunk_split($base64, 64, "\n"));
    return "-----BEGIN {$label}-----\n{$lines}\n-----END {$label}-----\n";
}

// ── Verifikacija potpisa ──────────────────────────────────────────

/**
 * Verifikuje WebAuthn potpis (registracija ILI autentikacija) koristeci
 * PEM javni kljuc dobijen od webauthn_cose_key_to_pem().
 *
 * Potpisani podaci = authenticatorData (sirovi bajtovi) || SHA256(clientDataJSON)
 * Ovo je definisano u WebAuthn spec za obe ceremonije (registration i assertion).
 */
function webauthn_verify_signature(
    string $authenticatorDataRaw,
    string $clientDataJsonRaw,
    string $signature,
    string $pem,
    int    $opensslAlgo = OPENSSL_ALGO_SHA256
): bool
{
    $clientDataHash = hash('sha256', $clientDataJsonRaw, true);
    $signedData = $authenticatorDataRaw . $clientDataHash;

    $publicKeyResource = openssl_pkey_get_public($pem);
    if ($publicKeyResource === false) {
        throw new RuntimeException('openssl_pkey_get_public neuspesan - los PEM format');
    }

    $result = openssl_verify($signedData, $signature, $publicKeyResource, $opensslAlgo);

    if ($result === -1) {
        throw new RuntimeException('openssl_verify greska: ' . openssl_error_string());
    }

    return $result === 1;
}