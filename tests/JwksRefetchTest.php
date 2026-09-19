<?php

declare(strict_types=1);

namespace Solis\Session\Tests;

use PHPUnit\Framework\TestCase;
use Solis\Session\Exception;
use Solis\Session\Jwks;

/**
 * An unknown kid forces one JWKS refresh (key rotation), but at most once per
 * refetch interval, failed attempts included — so tokens with made-up kids
 * cannot turn every request into a JWKS request to solis-identity. Mirrors the
 * Ruby solis-session (JwksCache#refresh!, 60 s).
 */
final class JwksRefetchTest extends TestCase
{
    private const URL = 'https://identity.example.com/.well-known/jwks.json';

    /** @var array<string,array<string,string>> kid => JWK */
    private static array $jwk = [];

    private string $cacheFile;
    private int $fetches = 0;

    public static function setUpBeforeClass(): void
    {
        foreach (['old', 'new'] as $kid) {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            $rsa = openssl_pkey_get_details($key)['rsa'];
            self::$jwk[$kid] = ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256',
                                'n' => self::b64u($rsa['n']), 'e' => self::b64u($rsa['e'])];
        }
    }

    private static function b64u(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    protected function setUp(): void
    {
        $this->cacheFile = tempnam(sys_get_temp_dir(), 'jwks');
        unlink($this->cacheFile);
        $this->fetches = 0;
    }

    protected function tearDown(): void
    {
        @unlink($this->cacheFile);
    }

    /**
     * A fetcher serving $docs in order (the last one repeats), counting calls.
     *
     * @param list<list<string>|null> $docs kid lists; null = the fetch fails
     */
    private function fetcher(array $docs): callable
    {
        return function (string $url) use ($docs): string {
            $doc = $docs[min($this->fetches, count($docs) - 1)];
            $this->fetches++;
            if ($doc === null) {
                throw new Exception('Unable to fetch JWKS from ' . $url);
            }
            return (string) json_encode(['keys' => array_map(fn ($kid) => self::$jwk[$kid], $doc)]);
        };
    }

    private function jwks(callable $fetcher, ?string $cacheFile = null): Jwks
    {
        return new Jwks(self::URL, 3600, $cacheFile, $fetcher);
    }

    public function testAnUnknownKidForcesOneRefreshAndResolves(): void
    {
        $jwks = $this->jwks($this->fetcher([['old'], ['new', 'old']]), $this->cacheFile);
        $this->assertInstanceOf(\OpenSSLAsymmetricKey::class, $jwks->publicKeyFor('new'));
        $this->assertSame(2, $this->fetches, 'the initial fetch, then one forced refresh');
    }

    public function testAKnownKidNeverForcesARefresh(): void
    {
        $jwks = $this->jwks($this->fetcher([['old']]), $this->cacheFile);
        $jwks->publicKeyFor('old');
        $jwks->publicKeyFor('old');
        $this->assertSame(1, $this->fetches);
    }

    public function testMadeUpKidsAcrossRequestsRefreshOncePerInterval(): void
    {
        $fetcher = $this->fetcher([['old']]);
        // A new Jwks per request, as under PHP-FPM, sharing the cache file.
        for ($i = 0; $i < 5; $i++) {
            try {
                $this->jwks($fetcher, $this->cacheFile)->publicKeyFor("forged-$i");
                $this->fail('a made-up kid must not resolve');
            } catch (Exception $e) {
                $this->assertStringContainsString('No JWKS key matches', $e->getMessage());
            }
        }
        $this->assertSame(2, $this->fetches, 'the initial fetch, then one forced refresh for all five');
    }

    public function testAFailedForcedRefreshAlsoCountsAgainstTheInterval(): void
    {
        $fetcher = $this->fetcher([['old'], null]);
        for ($i = 0; $i < 3; $i++) {
            try {
                $this->jwks($fetcher, $this->cacheFile)->publicKeyFor('new');
            } catch (Exception $e) {
                // first: the refresh fails; then: refused without a refresh
            }
        }
        $this->assertSame(2, $this->fetches);
    }

    public function testAfterTheIntervalAnotherRefreshIsAllowed(): void
    {
        $fetcher = $this->fetcher([['old'], ['old'], ['new', 'old']]);
        try {
            $this->jwks($fetcher, $this->cacheFile)->publicKeyFor('new');
        } catch (Exception $e) {
            // not rotated yet
        }
        $wrapped = json_decode((string) file_get_contents($this->cacheFile), true);
        $wrapped['refreshed_at'] -= 61;
        file_put_contents($this->cacheFile, json_encode($wrapped));

        $this->assertInstanceOf(\OpenSSLAsymmetricKey::class,
            $this->jwks($fetcher, $this->cacheFile)->publicKeyFor('new'));
        $this->assertSame(3, $this->fetches);
    }

    public function testTheStampSurvivesTheDocumentBeingRewritten(): void
    {
        $jwks = $this->jwks($this->fetcher([['old'], ['new', 'old']]), $this->cacheFile);
        $jwks->publicKeyFor('new');
        $wrapped = json_decode((string) file_get_contents($this->cacheFile), true);
        $this->assertArrayHasKey('refreshed_at', $wrapped);
        $this->assertArrayHasKey('doc', $wrapped);
        $this->assertSame(['new', 'old'], array_column($wrapped['doc']['keys'], 'kid'));
    }

    public function testWithoutACacheFileTheLimitHoldsPerInstance(): void
    {
        $jwks = $this->jwks($this->fetcher([['old']]));
        for ($i = 0; $i < 3; $i++) {
            try {
                $jwks->publicKeyFor("forged-$i");
            } catch (Exception $e) {
                // expected
            }
        }
        // No cross-request cache at all: each lookup reads the document again,
        // plus a single forced refresh for the whole run.
        $this->assertSame(4, $this->fetches);
    }
}
