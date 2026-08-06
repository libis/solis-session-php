<?php

declare(strict_types=1);

namespace Solis\Session;

/**
 * Fetches and caches solis-identity's JWKS, and resolves a key id (kid) to an
 * OpenSSL public-key resource. RSA public keys are reconstructed from the JWK
 * (modulus n + exponent e) by hand-building the ASN.1 DER SubjectPublicKeyInfo
 * — so the package needs no phpseclib/openssl-CLI, only ext-openssl.
 *
 * The cache is a single JSON file with a fetched-at stamp; on an unknown kid
 * (key rotation) the cache is force-refreshed once before giving up, so a
 * rotated signing key is picked up without a restart.
 */
final class Jwks
{
    private string $url;
    private int $ttl;
    private ?string $cacheFile;

    /** @var callable(string):string|null */
    private $fetcher;

    /** @var array<string,string> kid => PEM, built lazily */
    private array $pemCache = [];

    /**
     * @param string        $url       JWKS endpoint (…/.well-known/jwks.json)
     * @param int           $ttl       cache lifetime in seconds
     * @param string|null   $cacheFile path for the on-disk cache (null = memory only)
     * @param callable|null $fetcher   HTTP getter (string url): string body — override in tests
     */
    public function __construct(string $url, int $ttl = 3600, ?string $cacheFile = null, ?callable $fetcher = null)
    {
        $this->url = $url;
        $this->ttl = $ttl;
        $this->cacheFile = $cacheFile;
        $this->fetcher = $fetcher;
    }

    /**
     * Returns an OpenSSLAsymmetricKey for the given kid, refreshing the JWKS
     * once if the kid is unknown (rotation). Throws when it still can't be found.
     */
    public function publicKeyFor(?string $kid): \OpenSSLAsymmetricKey
    {
        $pem = $this->pemFor($kid, false) ?? $this->pemFor($kid, true);
        if ($pem === null) {
            throw new Exception('No JWKS key matches kid=' . ($kid ?? '(none)'));
        }
        $key = openssl_pkey_get_public($pem);
        if ($key === false) {
            throw new Exception('JWKS key for kid=' . ($kid ?? '(none)') . ' is not a usable public key');
        }
        return $key;
    }

    private function pemFor(?string $kid, bool $forceRefresh): ?string
    {
        $keys = $this->keys($forceRefresh);
        foreach ($keys as $jwk) {
            if (($jwk['kty'] ?? '') !== 'RSA') {
                continue;
            }
            // When the token carries no kid, accept the sole/first RSA key.
            if ($kid !== null && ($jwk['kid'] ?? null) !== $kid) {
                continue;
            }
            $cacheKey = (string) ($jwk['kid'] ?? 'default');
            return $this->pemCache[$cacheKey] ??= self::jwkToPem($jwk);
        }
        return null;
    }

    /**
     * @return array<int,array<string,mixed>>
     */
    private function keys(bool $forceRefresh): array
    {
        $doc = $this->document($forceRefresh);
        return is_array($doc['keys'] ?? null) ? $doc['keys'] : [];
    }

    /**
     * @return array<string,mixed>
     */
    private function document(bool $forceRefresh): array
    {
        if (!$forceRefresh) {
            $cached = $this->readCache();
            if ($cached !== null) {
                return $cached;
            }
        }
        $body = $this->fetch($this->url);
        $doc = json_decode($body, true);
        if (!is_array($doc)) {
            throw new Exception('JWKS endpoint returned invalid JSON');
        }
        $this->writeCache($doc);
        $this->pemCache = []; // invalidate reconstructed PEMs on refresh
        return $doc;
    }

    private function fetch(string $url): string
    {
        if ($this->fetcher !== null) {
            return ($this->fetcher)($url);
        }
        $ctx = stream_context_create(['http' => ['timeout' => 5], 'https' => ['timeout' => 5]]);
        $body = @file_get_contents($url, false, $ctx);
        if ($body === false) {
            throw new Exception('Unable to fetch JWKS from ' . $url);
        }
        return $body;
    }

    /**
     * @return array<string,mixed>|null
     */
    private function readCache(): ?array
    {
        if ($this->cacheFile === null || !is_file($this->cacheFile)) {
            return null;
        }
        $raw = @file_get_contents($this->cacheFile);
        if ($raw === false) {
            return null;
        }
        $wrapped = json_decode($raw, true);
        if (!is_array($wrapped) || !isset($wrapped['fetched_at'], $wrapped['doc'])) {
            return null;
        }
        if ((time() - (int) $wrapped['fetched_at']) > $this->ttl) {
            return null;
        }
        return is_array($wrapped['doc']) ? $wrapped['doc'] : null;
    }

    /**
     * @param array<string,mixed> $doc
     */
    private function writeCache(array $doc): void
    {
        if ($this->cacheFile === null) {
            return;
        }
        $payload = json_encode(['fetched_at' => time(), 'doc' => $doc]);
        @file_put_contents($this->cacheFile, $payload, LOCK_EX);
    }

    /**
     * Converts an RSA JWK to a PEM SubjectPublicKeyInfo ("PUBLIC KEY").
     *
     * @param array<string,mixed> $jwk
     */
    public static function jwkToPem(array $jwk): string
    {
        $n = self::b64uDecode((string) ($jwk['n'] ?? ''));
        $e = self::b64uDecode((string) ($jwk['e'] ?? ''));
        if ($n === '' || $e === '') {
            throw new Exception('RSA JWK missing modulus/exponent');
        }

        $rsaPublicKey = self::derSequence(
            self::derInteger($n) . self::derInteger($e)
        );
        // AlgorithmIdentifier: rsaEncryption (1.2.840.113549.1.1.1) + NULL params.
        $algId = self::derSequence(
            self::derOid("\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01") . self::derNull()
        );
        $spki = self::derSequence(
            $algId . self::derBitString($rsaPublicKey)
        );

        return "-----BEGIN PUBLIC KEY-----\n"
            . chunk_split(base64_encode($spki), 64, "\n")
            . "-----END PUBLIC KEY-----\n";
    }

    // ── ASN.1 DER primitives ────────────────────────────────────────────────

    private static function derLength(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = '';
        while ($len > 0) {
            $bytes = chr($len & 0xFF) . $bytes;
            $len >>= 8;
        }
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function derInteger(string $bytes): string
    {
        // Strip leading zero bytes, then re-add one if the high bit is set so
        // the integer is interpreted as positive (unsigned).
        $bytes = ltrim($bytes, "\x00");
        if ($bytes === '') {
            $bytes = "\x00";
        }
        if ((ord($bytes[0]) & 0x80) !== 0) {
            $bytes = "\x00" . $bytes;
        }
        return "\x02" . self::derLength(strlen($bytes)) . $bytes;
    }

    private static function derSequence(string $contents): string
    {
        return "\x30" . self::derLength(strlen($contents)) . $contents;
    }

    private static function derBitString(string $contents): string
    {
        // Leading 0x00 = number of unused bits in the final byte.
        return "\x03" . self::derLength(strlen($contents) + 1) . "\x00" . $contents;
    }

    private static function derOid(string $encoded): string
    {
        return "\x06" . self::derLength(strlen($encoded)) . $encoded;
    }

    private static function derNull(): string
    {
        return "\x05\x00";
    }

    public static function b64uDecode(string $data): string
    {
        $data = strtr($data, '-_', '+/');
        $pad = strlen($data) % 4;
        if ($pad > 0) {
            $data .= str_repeat('=', 4 - $pad);
        }
        $decoded = base64_decode($data, true);
        return $decoded === false ? '' : $decoded;
    }
}
