<?php

declare(strict_types=1);

namespace Solis\Session\Tests;

use PHPUnit\Framework\TestCase;
use Solis\Session\AttributesClient;
use Solis\Session\Claims;
use Solis\Session\Exception;

// AttributesClient reads and writes user attributes on solis-identity. Unlike
// KvClient it reads as well as writes, because attributes never reach a token —
// an app has to ask for them. The HTTP seam is injected (transport) so no real
// request / running identity is needed.
final class AttributesClientTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $calls = [];

    private function transport(int $status = 200, ?string $body = null): callable
    {
        $body ??= json_encode(['attributes' => []]);
        return function (string $method, string $url, array $headers, ?string $reqBody) use ($status, $body) {
            $this->calls[] = compact('method', 'url', 'headers', 'reqBody');
            return [$status, $body];
        };
    }

    private function client(callable $transport, array $opts = []): AttributesClient
    {
        return new AttributesClient(
            'https://identity.example.com',
            'raw-key',
            array_merge(['transport' => $transport], $opts)
        );
    }

    // ── Construction ─────────────────────────────────────────────────────────

    public function testRequiresIdentityBaseAndApiKey(): void
    {
        $this->expectException(Exception::class);
        new AttributesClient('', 'raw-key');
    }

    public function testRequiresApiKey(): void
    {
        $this->expectException(Exception::class);
        new AttributesClient('https://identity.example.com', '  ');
    }

    public function testMountpointIsApplied(): void
    {
        $this->client($this->transport(), ['mountpoint' => '_'])->all('jane@example.com');
        $this->assertSame(
            'https://identity.example.com/_/api/users/jane%40example.com/attributes',
            $this->calls[0]['url']
        );
    }

    // ── Reading ──────────────────────────────────────────────────────────────

    public function testAllIssuesGetWithApiKey(): void
    {
        $res = $this->client($this->transport(200, json_encode(['attributes' => ['orcid' => '0000-1']])))
                    ->all('jane@example.com');

        $c = $this->calls[0];
        $this->assertSame('GET', $c['method']);
        $this->assertSame('https://identity.example.com/api/users/jane%40example.com/attributes', $c['url']);
        $this->assertContains('Authorization: ApiKey raw-key', $c['headers']);
        $this->assertNull($c['reqBody']);
        $this->assertSame(['orcid' => '0000-1'], $res);
    }

    public function testGetSingleKey(): void
    {
        $res = $this->client($this->transport(200, json_encode(['key' => 'orcid', 'value' => '0000-1'])))
                    ->get('jane@example.com', 'orcid');

        $this->assertSame(
            'https://identity.example.com/api/users/jane%40example.com/attributes/orcid',
            $this->calls[0]['url']
        );
        $this->assertSame('0000-1', $res);
    }

    // The server 404s an absent key so it stays distinct from a stored null; a
    // caller reaching for one value just wants null.
    public function testGetReturnsNullForMissingKey(): void
    {
        $res = $this->client($this->transport(404, json_encode(['error' => 'not_found'])))
                    ->get('jane@example.com', 'nope');
        $this->assertNull($res);
    }

    // Any other failure is still an error — only 404 collapses to null.
    public function testGetRaisesOnOtherStatuses(): void
    {
        $this->expectException(Exception::class);
        $this->client($this->transport(403, json_encode(['error' => 'insufficient_scope'])))
             ->get('jane@example.com', 'x');
    }

    public function testKeysAreUrlEncoded(): void
    {
        $this->client($this->transport(200, json_encode(['value' => 1])))
             ->get('jane@example.com', 'a b/c');
        $this->assertStringContainsString('/attributes/a%20b%2Fc', $this->calls[0]['url']);
    }

    // ── Writing ──────────────────────────────────────────────────────────────

    public function testSetIssuesPutWithValueBody(): void
    {
        $res = $this->client($this->transport(200, json_encode(['key' => 'seats', 'value' => 5])))
                    ->set('jane@example.com', 'seats', 5);

        $c = $this->calls[0];
        $this->assertSame('PUT', $c['method']);
        $this->assertContains('Content-Type: application/json', $c['headers']);
        $this->assertSame(['value' => 5], json_decode($c['reqBody'], true));
        $this->assertSame(5, $res);
    }

    public function testSetSerializesComplexValues(): void
    {
        $this->client($this->transport(200, json_encode(['value' => ['theme' => 'dark']])))
             ->set('jane@example.com', 'prefs', ['theme' => 'dark']);
        $this->assertSame(
            ['value' => ['theme' => 'dark']],
            json_decode($this->calls[0]['reqBody'], true)
        );
    }

    public function testMergeIssuesPatch(): void
    {
        $res = $this->client($this->transport(200, json_encode(['attributes' => ['a' => 1]])))
                    ->merge('jane@example.com', ['a' => 1, 'b' => null]);

        $c = $this->calls[0];
        $this->assertSame('PATCH', $c['method']);
        $this->assertSame(['attributes' => ['a' => 1, 'b' => null]], json_decode($c['reqBody'], true));
        $this->assertSame(['a' => 1], $res);
    }

    public function testReplaceIssuesPutOnTheCollection(): void
    {
        $res = $this->client($this->transport(200, json_encode(['attributes' => ['only' => 'this']])))
                    ->replace('jane@example.com', ['only' => 'this']);

        $c = $this->calls[0];
        $this->assertSame('PUT', $c['method']);
        $this->assertSame('https://identity.example.com/api/users/jane%40example.com/attributes', $c['url']);
        $this->assertSame(['attributes' => ['only' => 'this']], json_decode($c['reqBody'], true));
        $this->assertSame(['only' => 'this'], $res);
    }

    public function testDeleteIssuesDeleteWithoutBody(): void
    {
        $res = $this->client($this->transport(200, json_encode(['deleted' => true])))
                    ->delete('jane@example.com', 'seats');

        $c = $this->calls[0];
        $this->assertSame('DELETE', $c['method']);
        $this->assertNull($c['reqBody']);
        $this->assertNotContains('Content-Type: application/json', $c['headers']);
        $this->assertTrue($res);
    }

    public function testDeleteReportsFalseWhenAbsent(): void
    {
        $res = $this->client($this->transport(200, json_encode(['deleted' => false])))
                    ->delete('jane@example.com', 'gone');
        $this->assertFalse($res);
    }

    public function testClearDeletesTheCollection(): void
    {
        $this->client($this->transport(200, json_encode(['attributes' => []])))
             ->clear('jane@example.com');
        $this->assertSame('DELETE', $this->calls[0]['method']);
        $this->assertSame('https://identity.example.com/api/users/jane%40example.com/attributes', $this->calls[0]['url']);
    }

    // ── Errors ───────────────────────────────────────────────────────────────

    public function testNon200RaisesWithStatusAndBody(): void
    {
        try {
            $this->client($this->transport(403, json_encode(['error' => 'insufficient_scope'])))
                 ->all('jane@example.com');
            $this->fail('expected Exception');
        } catch (Exception $e) {
            $this->assertSame(403, $e->getCode());
            $this->assertStringContainsString('403', $e->getMessage());
            $this->assertStringContainsString('insufficient_scope', $e->getMessage());
        }
    }

    public function testUnparseableBodyDoesNotBlowUp(): void
    {
        $res = $this->client($this->transport(200, 'not json'))->all('jane@example.com');
        $this->assertSame([], $res);
    }

    // ── Session convenience ──────────────────────────────────────────────────

    public function testForClaimsUsesTheValidatedUsersEmail(): void
    {
        $claims = new Claims(['sub' => 'jane@example.com', 'email' => 'jane@example.com']);
        $res = $this->client($this->transport(200, json_encode(['attributes' => ['theme' => 'dark']])))
                    ->forClaims($claims);

        $this->assertStringContainsString('jane%40example.com', $this->calls[0]['url']);
        $this->assertSame(['theme' => 'dark'], $res);
    }

    // Guest mode: no session means no request at all, not an exception.
    public function testForClaimsReturnsEmptyWithoutASession(): void
    {
        $this->assertSame([], $this->client($this->transport())->forClaims(null));
        $this->assertSame([], $this->client($this->transport())->forClaims(new Claims([])));
        $this->assertSame([], $this->calls);
    }
}
