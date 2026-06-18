<?php
/**
 * cbor.php - Minimalan CBOR (RFC 8949) decoder
 *
 * WebAuthn koristi CBOR samo za ogranicen podskup tipova:
 * unsigned/negative integers, byte strings, text strings, arrays, maps,
 * i nekoliko simple values (true/false/null). Ovaj decoder pokriva
 * TACNO to, ne ceo CBOR standard (npr. nema tags, floats, indefinite-length
 * koji se rede koriste u attestationObject/COSE key strukturama koje nas
 * interesuju, ali ako naletis na njih dobices Exception umesto pogresnog
 * rezultata - sigurnije nego tiho davati los podatak).
 *
 * Koristi se za:
 *  - Dekodiranje attestationObject (mapa: fmt, attStmt, authData)
 *  - Dekodiranje COSE javnog kljuca iz authData (mapa: kty, alg, crv, x, y)
 */

final class CborDecoder
{
    private string $data;
    private int $offset = 0;

    public function __construct(string $binary)
    {
        $this->data = $binary;
    }

    public static function decode(string $binary): mixed
    {
        $decoder = new self($binary);
        $value = $decoder->decodeItem();
        return $value;
    }

    /**
     * Dekodira jedan CBOR item i vraca i preostali offset (korisno kad
     * iza CBOR strukture ima jos sirovih bajtova, kao u attestationObject->authData).
     */
    public static function decodeWithOffset(string $binary, int $startOffset = 0): array
    {
        $decoder = new self($binary);
        $decoder->offset = $startOffset;
        $value = $decoder->decodeItem();
        return [$value, $decoder->offset];
    }

    private function readByte(): int
    {
        if ($this->offset >= strlen($this->data)) {
            throw new RuntimeException('CBOR: neocekivan kraj podataka');
        }
        return ord($this->data[$this->offset++]);
    }

    private function readBytes(int $n): string
    {
        if ($this->offset + $n > strlen($this->data)) {
            throw new RuntimeException('CBOR: neocekivan kraj podataka (readBytes)');
        }
        $bytes = substr($this->data, $this->offset, $n);
        $this->offset += $n;
        return $bytes;
    }

    private function readUint(int $n): int|string
    {
        $bytes = $this->readBytes($n);
        if ($n <= 4) {
            return (int) hexdec(bin2hex($bytes));
        }
        // 8-bajtni unsigned integer - vrati kao string ako prelazi PHP int opseg
        $hex = bin2hex($bytes);
        $val = hexdec($hex);
        return $val;
    }

    private function decodeItem(): mixed
    {
        $initialByte = $this->readByte();
        $majorType   = $initialByte >> 5;
        $additional  = $initialByte & 0x1F;

        return match ($majorType) {
            0 => $this->decodeUnsignedInt($additional),               // unsigned integer
            1 => -1 - $this->decodeUnsignedInt($additional),           // negative integer
            2 => $this->decodeByteString($additional),                 // byte string
            3 => $this->decodeTextString($additional),                 // text string
            4 => $this->decodeArray($additional),                      // array
            5 => $this->decodeMap($additional),                        // map
            6 => $this->decodeTagged($additional),                     // tagged item (npr. bignum) - rijetko u WebAuthn
            7 => $this->decodeSimpleOrFloat($additional),              // simple/float/break
            default => throw new RuntimeException("CBOR: nepoznat major type $majorType"),
        };
    }

    private function decodeUnsignedInt(int $additional): int|string
    {
        if ($additional < 24)  return $additional;
        if ($additional === 24) return $this->readUint(1);
        if ($additional === 25) return $this->readUint(2);
        if ($additional === 26) return $this->readUint(4);
        if ($additional === 27) return $this->readUint(8);
        throw new RuntimeException('CBOR: nepodrzana duzina unsigned int (indefinite?)');
    }

    private function decodeByteString(int $additional): string
    {
        $len = $this->decodeUnsignedInt($additional);
        return $this->readBytes((int)$len);
    }

    private function decodeTextString(int $additional): string
    {
        $len = $this->decodeUnsignedInt($additional);
        return $this->readBytes((int)$len);
    }

    private function decodeArray(int $additional): array
    {
        $len = $this->decodeUnsignedInt($additional);
        $arr = [];
        for ($i = 0; $i < $len; $i++) {
            $arr[] = $this->decodeItem();
        }
        return $arr;
    }

    private function decodeMap(int $additional): array
    {
        $len = $this->decodeUnsignedInt($additional);
        $map = [];
        for ($i = 0; $i < $len; $i++) {
            $key   = $this->decodeItem();
            $value = $this->decodeItem();
            $map[$key] = $value;
        }
        return $map;
    }

    private function decodeTagged(int $additional): mixed
    {
        // Tag broj se cita, ali za WebAuthn svrhe samo prosledjujemo
        // sledeci item bez posebne obrade (npr. bignum tagovi 2/3 za RSA modulus).
        $this->decodeUnsignedInt($additional);
        return $this->decodeItem();
    }

    private function decodeSimpleOrFloat(int $additional): mixed
    {
        return match ($additional) {
            20 => false,
            21 => true,
            22 => null,
            23 => null, // undefined
            25 => $this->readFloat16(),
            26 => $this->readFloat32(),
            27 => $this->readFloat64(),
            default => throw new RuntimeException("CBOR: nepodrzan simple/float additional=$additional"),
        };
    }

    private function readFloat16(): float
    {
        $bytes = $this->readBytes(2);
        $bits  = unpack('n', $bytes)[1];
        $sign  = ($bits & 0x8000) ? -1 : 1;
        $exp   = ($bits >> 10) & 0x1F;
        $frac  = $bits & 0x3FF;
        if ($exp === 0) return $sign * (2 ** -14) * ($frac / 1024);
        if ($exp === 0x1F) return $frac ? NAN : $sign * INF;
        return $sign * (2 ** ($exp - 15)) * (1 + $frac / 1024);
    }

    private function readFloat32(): float
    {
        $bytes = $this->readBytes(4);
        return unpack('G', $bytes)[1]; // big-endian float
    }

    private function readFloat64(): float
    {
        $bytes = $this->readBytes(8);
        return unpack('E', $bytes)[1]; // big-endian double
    }

    public function getOffset(): int
    {
        return $this->offset;
    }
}