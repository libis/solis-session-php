<?php

declare(strict_types=1);

namespace Solis\Session\Tests;

use PHPUnit\Framework\TestCase;
use Solis\Session\Claims;
use Solis\Session\Exception;
use Solis\Session\Jwks;
use Solis\Session\Jwt;
use Solis\Session\Session;

/**
 * Wire-format interop: the fixtures in tests/fixtures mirror the exact JWKS
 * shape and RS256 signing that solis-identity's JwtIssuer emits — same header
 * key order, same JWK member order, same unpadded base64url. If these pass,
 * the verifier handles the wire format it will meet in production.
 *
 * Regenerate with `php tests/fixtures/generate.php` (see README).
 */
final class InteropTest extends TestCase
{
    private function jwks(): Jwks
    {
        $json = (string) file_get_contents(__DIR__ . '/fixtures/jwks.json');
        // Offline fetcher: return the fixture JWKS instead of hitting the network.
        return new Jwks('https://identity.example.com/.well-known/jwks.json', 3600, null, fn () => $json);
    }

    private function token(string $name): string
    {
        return trim((string) file_get_contents(__DIR__ . "/fixtures/$name"));
    }

    public function testJwkToPemMatchesOpenSsl(): void
    {
        $jwk = json_decode((string) file_get_contents(__DIR__ . '/fixtures/jwks.json'), true)['keys'][0];
        $pem = Jwks::jwkToPem($jwk);
        $key = openssl_pkey_get_public($pem);
        $this->assertNotFalse($key, 'reconstructed JWK must be a usable public key');
        $details = openssl_pkey_get_details($key);
        $this->assertSame(OPENSSL_KEYTYPE_RSA, $details['type']);
    }

    public function testVerifiesValidSignedToken(): void
    {
        $claims = Jwt::verify($this->token('token_valid.txt'), $this->jwks());
        $this->assertSame('jane@example.com', $claims['email']);
        $this->assertSame('acme', $claims['tenant']);
        $this->assertSame(['content-editor'], $claims['app_roles']['intranet']);
        $this->assertTrue($claims['fee_paid']);
    }

    public function testRejectsExpiredToken(): void
    {
        $this->expectException(Exception::class);
        Jwt::verify($this->token('token_expired.txt'), $this->jwks());
    }

    public function testRejectsBadSignature(): void
    {
        $this->expectException(Exception::class);
        Jwt::verify($this->token('token_badsig.txt'), $this->jwks());
    }

    public function testRejectsTamperedPayload(): void
    {
        $token = $this->token('token_valid.txt');
        [$h, $p, $s] = explode('.', $token);
        $payload = json_decode(Jwks::b64uDecode($p), true);
        $payload['roles'] = ['super_admin']; // privilege escalation attempt
        $forged = rtrim(strtr(base64_encode(json_encode($payload)), '+/', '-_'), '=');
        $this->expectException(Exception::class);
        Jwt::verify("$h.$forged.$s", $this->jwks());
    }

    public function testAlgNoneRejected(): void
    {
        // header {alg:none}, same payload, empty signature.
        $token = $this->token('token_valid.txt');
        [, $p] = explode('.', $token);
        $h = rtrim(strtr(base64_encode(json_encode(['alg' => 'none', 'typ' => 'JWT'])), '+/', '-_'), '=');
        $this->expectException(Exception::class);
        Jwt::verify("$h.$p.", $this->jwks());
    }

    public function testClaimsAccessors(): void
    {
        $payload = Jwt::verify($this->token('token_valid.txt'), $this->jwks());
        $claims = new Claims($payload);
        $this->assertSame('Jane Editor', $claims->name());
        $this->assertTrue($claims->hasRole('member'));
        $this->assertFalse($claims->isSuperAdmin());
        $this->assertTrue($claims->hasAppRole('intranet', 'content-editor'));
        $this->assertFalse($claims->hasAppRole('intranet', 'admin'));
        $this->assertTrue($claims->feePaid());
    }

    public function testSessionReadsBearerHeaderAndValidates(): void
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $this->token('token_valid.txt');
        $session = new Session('https://identity.example.com', [
            'jwks' => $this->jwks(),
        ]);
        $claims = $session->authenticate();
        $this->assertNotNull($claims);
        $this->assertSame('acme', $claims->tenant());
        unset($_SERVER['HTTP_AUTHORIZATION']);
    }

    public function testSessionReturnsNullWithoutToken(): void
    {
        unset($_SERVER['HTTP_AUTHORIZATION'], $_COOKIE[Session::COOKIE_NAME]);
        $session = new Session('https://identity.example.com', ['jwks' => $this->jwks()]);
        $this->assertNull($session->authenticate());
        $this->assertFalse($session->isAuthenticated());
    }

    public function testLoginUrlBuiltFromTenantAndCurrentUrl(): void
    {
        $_SERVER['HTTP_HOST'] = 'intranet.example.com';
        $_SERVER['REQUEST_URI'] = '/working-groups/notes';
        $_SERVER['HTTPS'] = 'on';
        $session = new Session('https://identity.example.com', ['jwks' => $this->jwks()]);
        $url = $session->loginUrl('acme');
        $this->assertStringStartsWith('https://identity.example.com/acme/login?return_to=', $url);
        $this->assertStringContainsString(rawurlencode('https://intranet.example.com/working-groups/notes'), $url);
    }

    /**
     * The mountpoint is optional: identity at the root of its own host is the
     * default. An absent or empty value must contribute no path segment at
     * all — not a bare '/', which would yield '//.well-known/jwks.json'.
     *
     * @dataProvider mountpointCases
     */
    public function testMountpointIsOptionalAndNeverDoubleSlashes(
        array $options,
        string $expectedLogin
    ): void {
        $session = new Session('https://identity.example.com', $options + ['jwks' => $this->jwks()]);
        $url = $session->loginUrl('acme');
        // loginUrl always appends ?return_to=, so match the path prefix.
        $this->assertStringStartsWith($expectedLogin . '?return_to=', $url);
        $this->assertStringNotContainsString('.com//', $url);
    }

    public static function mountpointCases(): array
    {
        $root = 'https://identity.example.com/acme/login';
        return [
            'absent'          => [[], $root],
            'empty string'    => [['mountpoint' => ''], $root],
            'bare slash'      => [['mountpoint' => '/'], $root],
            'bare segment'    => [['mountpoint' => '_'], 'https://identity.example.com/_/acme/login'],
            'leading slash'   => [['mountpoint' => '/_'], 'https://identity.example.com/_/acme/login'],
            'both slashes'    => [['mountpoint' => '/_/'], 'https://identity.example.com/_/acme/login'],
        ];
    }

    public function testGuestRoleFromDiscoveryDocument(): void
    {
        $disco = json_encode(['app_guest_roles' => ['intranet' => 'guest_reader']]);
        $session = new Session('https://identity.example.com', [
            'service_name' => 'intranet',
            'jwks' => $this->jwks(),
            'fetcher' => fn () => $disco,
        ]);
        $this->assertSame('guest_reader', $session->guestRole());
    }
}
