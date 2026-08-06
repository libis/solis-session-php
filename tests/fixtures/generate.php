<?php

declare(strict_types=1);

/**
 * Regenerates the interop fixtures in this directory.
 *
 *   php tests/fixtures/generate.php
 *
 * The fixtures mirror the exact JWKS shape and RS256 signing that
 * solis-identity's JwtIssuer emits — same header key order, same JWK member
 * order, same base64url-without-padding encoding — so a green suite exercises
 * the verifier against the wire format it will meet in production.
 *
 * The signing keys are generated here and deliberately thrown away: nothing
 * but the public half is ever written to disk, and the claims are fictional
 * (see $payload below). Never point this at a real deployment's keys.
 *
 * Output is deterministic apart from the RSA keys themselves, which are new on
 * every run — regenerating changes jwks.json and all three tokens together.
 */

const KID = 'test-key-1';

/** base64url, no padding — what JWT and JWK both use. */
function b64u(string $bin): string
{
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

function newKey(): \OpenSSLAsymmetricKey
{
    $key = openssl_pkey_new([
        'private_key_bits' => 2048,
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
    ]);
    if ($key === false) {
        fwrite(STDERR, "openssl_pkey_new failed: " . openssl_error_string() . "\n");
        exit(1);
    }
    return $key;
}

/** Sign $payload with $key, emitting the header solis-identity emits. */
function mint(array $payload, \OpenSSLAsymmetricKey $key): string
{
    // Key order matters: this is the byte-for-byte header shape being mirrored.
    $header = b64u((string) json_encode(['kid' => KID, 'alg' => 'RS256']));
    $body   = b64u((string) json_encode($payload));
    $input  = "$header.$body";

    $sig = '';
    if (!openssl_sign($input, $sig, $key, OPENSSL_ALGO_SHA256)) {
        fwrite(STDERR, "openssl_sign failed: " . openssl_error_string() . "\n");
        exit(1);
    }
    return "$input." . b64u($sig);
}

$signing = newKey();
// A second, unrelated key. token_badsig is signed with this one, so it carries
// a structurally valid RS256 signature that simply isn't the JWKS key's —
// a truer negative than corrupted bytes, which could fail for the wrong reason.
$foreign = newKey();

$details = openssl_pkey_get_details($signing);

$jwks = ['keys' => [[
    'kty' => 'RSA',
    'use' => 'sig',
    'kid' => KID,
    'alg' => 'RS256',
    'n'   => b64u($details['rsa']['n']),
    'e'   => b64u($details['rsa']['e']),
]]];

$iat = 1750000000;                 // 2025-06-15T14:26:40Z, fixed so fixtures don't drift
$payload = [
    'sub'                => 'jane@example.com',
    'email'              => 'jane@example.com',
    'preferred_username' => 'Jane Editor',
    'tenant'             => 'acme',
    'application'        => 'intranet',
    'roles'              => ['member'],
    'app_roles'          => ['intranet' => ['content-editor']],
    'groups'             => [],
    'fee_paid'           => true,
    'iss'                => 'https://identity.example.com',
    'aud'                => ['intranet'],
    'iat'                => $iat,
    'exp'                => 4102444800,   // 2100-01-01, far enough out not to rot
];

// array_merge, not +, so the claim order matches the valid token exactly and
// only exp differs.
$expired = array_merge($payload, ['exp' => $iat + 100]);

$out = [
    'jwks.json'         => json_encode($jwks, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n",
    'token_valid.txt'   => mint($payload, $signing) . "\n",
    'token_expired.txt' => mint($expired, $signing) . "\n",
    'token_badsig.txt'  => mint($payload, $foreign) . "\n",
];

foreach ($out as $name => $contents) {
    file_put_contents(__DIR__ . '/' . $name, $contents);
    printf("wrote %s (%d bytes)\n", $name, strlen($contents));
}
