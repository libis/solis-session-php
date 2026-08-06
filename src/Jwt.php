<?php

declare(strict_types=1);

namespace Solis\Session;

/**
 * Minimal RS256 JWT verifier built on ext-openssl. Verifies the signature
 * against a JWKS-resolved key and enforces exp / nbf / iat with a small clock
 * skew. Only RS256 is accepted — the algorithm is pinned, never read from the
 * (attacker-controlled) header, so the classic "alg: none" / HS256 confusion
 * attacks don't apply.
 */
final class Jwt
{
    public const ALG = 'RS256';

    /**
     * @param  int  $leewaySeconds tolerance for clock skew on exp/nbf/iat
     * @return array<string,mixed> the verified claim set
     */
    public static function verify(string $token, Jwks $jwks, int $leewaySeconds = 60, ?int $now = null): array
    {
        $now ??= time();
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new Exception('Malformed JWT (expected 3 segments)');
        }
        [$h64, $p64, $s64] = $parts;

        $header = self::decodeSegment($h64, 'header');
        if (($header['alg'] ?? null) !== self::ALG) {
            throw new Exception('Unsupported JWT alg; only ' . self::ALG . ' is accepted');
        }

        $key = $jwks->publicKeyFor(isset($header['kid']) ? (string) $header['kid'] : null);
        $signature = Jwks::b64uDecode($s64);
        $signingInput = $h64 . '.' . $p64;

        $ok = openssl_verify($signingInput, $signature, $key, OPENSSL_ALGO_SHA256);
        if ($ok !== 1) {
            throw new Exception('JWT signature verification failed');
        }

        $claims = self::decodeSegment($p64, 'payload');
        self::assertTime($claims, $now, $leewaySeconds);
        return $claims;
    }

    /**
     * @param array<string,mixed> $claims
     */
    private static function assertTime(array $claims, int $now, int $leeway): void
    {
        if (isset($claims['exp']) && $now > ((int) $claims['exp'] + $leeway)) {
            throw new Exception('JWT has expired');
        }
        if (isset($claims['nbf']) && $now < ((int) $claims['nbf'] - $leeway)) {
            throw new Exception('JWT not yet valid (nbf)');
        }
        if (isset($claims['iat']) && $now < ((int) $claims['iat'] - $leeway)) {
            throw new Exception('JWT issued in the future (iat)');
        }
    }

    /**
     * @return array<string,mixed>
     */
    private static function decodeSegment(string $segment, string $what): array
    {
        $json = Jwks::b64uDecode($segment);
        $data = json_decode($json, true);
        if (!is_array($data)) {
            throw new Exception("Invalid JWT $what encoding");
        }
        return $data;
    }
}
