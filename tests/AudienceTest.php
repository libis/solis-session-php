<?php

declare(strict_types=1);

namespace Solis\Session\Tests;

use PHPUnit\Framework\TestCase;
use Solis\Session\Exception;
use Solis\Session\Jwks;
use Solis\Session\Jwt;
use Solis\Session\Session;

/**
 * Audience enforcement. With `service_name` set, a token must name that service
 * in `aud` — the same rule the Ruby middleware applies through TokenValidator.
 * Without it, a valid token issued for any other application would open this one.
 */
final class AudienceTest extends TestCase
{
    private const KID = 'aud-test-key';

    private static \OpenSSLAsymmetricKey $key;
    private static string $jwksJson;

    public static function setUpBeforeClass(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        self::$key = $key;

        $rsa = openssl_pkey_get_details($key)['rsa'];
        self::$jwksJson = (string) json_encode(['keys' => [[
            'kty' => 'RSA', 'use' => 'sig', 'kid' => self::KID, 'alg' => 'RS256',
            'n'   => self::b64u($rsa['n']), 'e' => self::b64u($rsa['e']),
        ]]]);
    }

    protected function tearDown(): void
    {
        unset($_SERVER['HTTP_AUTHORIZATION'], $_COOKIE[Session::COOKIE_NAME]);
    }

    private static function b64u(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    /** @param array<string,mixed> $claims */
    private static function mint(array $claims): string
    {
        $input = self::b64u((string) json_encode(['kid' => self::KID, 'alg' => 'RS256']))
            . '.' . self::b64u((string) json_encode($claims + [
                'sub' => 'jane@example.com', 'tenant' => 'acme', 'iat' => time(), 'exp' => time() + 600,
            ]));
        openssl_sign($input, $sig, self::$key, OPENSSL_ALGO_SHA256);
        return $input . '.' . self::b64u($sig);
    }

    private function jwks(): Jwks
    {
        $json = self::$jwksJson;
        return new Jwks('https://identity.example.com/.well-known/jwks.json', 3600, null, fn () => $json);
    }

    private function sessionFor(string $token, ?string $serviceName): Session
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $token;
        $options = ['jwks' => $this->jwks()];
        if ($serviceName !== null) {
            $options['service_name'] = $serviceName;
        }
        return new Session('https://identity.example.com', $options);
    }

    // ── Jwt::verify ──────────────────────────────────────────────────────

    public function testVerifyAcceptsAMatchingAudience(): void
    {
        $claims = Jwt::verify(self::mint(['aud' => ['dam', 'cms']]), $this->jwks(), 60, null, 'cms');
        self::assertSame('acme', $claims['tenant']);
    }

    public function testVerifyRejectsAnotherApplicationsToken(): void
    {
        $this->expectException(Exception::class);
        Jwt::verify(self::mint(['aud' => ['cms']]), $this->jwks(), 60, null, 'dam');
    }

    // RFC 7519 allows aud as a single string.
    public function testVerifyAcceptsAStringAudience(): void
    {
        $claims = Jwt::verify(self::mint(['aud' => 'dam']), $this->jwks(), 60, null, 'dam');
        self::assertSame('dam', $claims['aud']);
    }

    // A token naming no audience cannot be shown to be meant for this service.
    public function testVerifyRejectsAMissingAudienceWhenOneIsRequired(): void
    {
        $this->expectException(Exception::class);
        Jwt::verify(self::mint([]), $this->jwks(), 60, null, 'dam');
    }

    public function testVerifyRejectsAPrefixMatch(): void
    {
        $this->expectException(Exception::class);
        Jwt::verify(self::mint(['aud' => ['dam-staging']]), $this->jwks(), 60, null, 'dam');
    }

    // No audience asked for: unchanged behaviour for callers that verify tokens
    // not addressed to one service.
    public function testVerifyWithoutAnAudienceSkipsTheCheck(): void
    {
        $claims = Jwt::verify(self::mint(['aud' => ['cms']]), $this->jwks());
        self::assertSame(['cms'], $claims['aud']);
    }

    // ── Session ──────────────────────────────────────────────────────────

    public function testSessionAcceptsATokenForThisService(): void
    {
        $claims = $this->sessionFor(self::mint(['aud' => ['dam']]), 'dam')->authenticate();
        self::assertNotNull($claims);
    }

    public function testSessionTreatsAnotherApplicationsTokenAsNoSession(): void
    {
        $session = $this->sessionFor(self::mint(['aud' => ['cms']]), 'dam');
        self::assertNull($session->authenticate());
        self::assertFalse($session->isAuthenticated());
    }

    public function testSessionWithoutServiceNameDoesNotCheckAudience(): void
    {
        self::assertNotNull($this->sessionFor(self::mint(['aud' => ['cms']]), null)->authenticate());
    }

    // The committed interop fixture carries aud ["intranet"].
    public function testInteropFixtureRespectsAudience(): void
    {
        $fixtures = __DIR__ . '/fixtures';
        $json     = (string) file_get_contents("$fixtures/jwks.json");
        $jwks     = new Jwks('https://identity.example.com/.well-known/jwks.json', 3600, null, fn () => $json);
        $token    = trim((string) file_get_contents("$fixtures/token_valid.txt"));

        self::assertNotEmpty(Jwt::verify($token, $jwks, 60, null, 'intranet'));

        $this->expectException(Exception::class);
        Jwt::verify($token, $jwks, 60, null, 'dam');
    }
}
