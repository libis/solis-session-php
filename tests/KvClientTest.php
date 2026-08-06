<?php

declare(strict_types=1);

namespace Solis\Session\Tests;

use PHPUnit\Framework\TestCase;
use Solis\Session\Exception;
use Solis\Session\KvClient;

// The HTTP seam is injected (transport) so no real request / running identity
// is needed; tests assert the exact request shape and error handling.
final class KvClientTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $calls = [];

    private function transport(int $status = 200, ?string $body = null): callable
    {
        $body ??= json_encode(['ok' => true]);
        return function (string $method, string $url, array $headers, ?string $reqBody) use (&$status, $body) {
            $this->calls[] = compact('method', 'url', 'headers', 'reqBody');
            return [$status, $body];
        };
    }

    private function client(callable $transport, array $opts = []): KvClient
    {
        return new KvClient('https://identity.example.com', 'raw-key', array_merge(['transport' => $transport], $opts));
    }

    public function testSetIssuesPutWithValueBodyAndApiKey(): void
    {
        $res = $this->client($this->transport(200, json_encode(['ok' => true, 'namespace' => 'fee_paid'])))
                    ->set('fee_paid', 'acme', true);

        $c = $this->calls[0];
        $this->assertSame('PUT', $c['method']);
        $this->assertSame('https://identity.example.com/kv/fee_paid/acme', $c['url']);
        $this->assertContains('Authorization: ApiKey raw-key', $c['headers']);
        $this->assertContains('Content-Type: application/json', $c['headers']);
        $this->assertSame(['value' => true], json_decode($c['reqBody'], true));
        $this->assertTrue($res['ok']);
    }

    public function testSetSerializesComplexValues(): void
    {
        $this->client($this->transport())->set('quota', 'acme', ['seats' => 50]);
        $this->assertSame(['value' => ['seats' => 50]], json_decode($this->calls[0]['reqBody'], true));
    }

    public function testDeleteIssuesDeleteWithoutBody(): void
    {
        $res = $this->client($this->transport(200, json_encode(['ok' => true, 'deleted' => true])))
                    ->delete('fee_paid', 'acme');

        $c = $this->calls[0];
        $this->assertSame('DELETE', $c['method']);
        $this->assertNull($c['reqBody']);
        $this->assertNotContains('Content-Type: application/json', $c['headers']);
        $this->assertTrue($res['deleted']);
    }

    public function testEmailKeyIsPathEncoded(): void
    {
        $this->client($this->transport())->set('member_status', 'a.walker@example.org', 'active');
        $this->assertSame(
            'https://identity.example.com/kv/member_status/a.walker%40example.org',
            $this->calls[0]['url']
        );
    }

    public function testMountpointIsPrefixed(): void
    {
        $this->client($this->transport(), ['mountpoint' => '_'])->set('fee_paid', 'x', true);
        $this->assertSame('https://identity.example.com/_/kv/fee_paid/x', $this->calls[0]['url']);
    }

    public function testBlankMountpointAddsNoSegment(): void
    {
        $this->client($this->transport(), ['mountpoint' => ''])->set('fee_paid', 'x', true);
        $this->assertSame('https://identity.example.com/kv/fee_paid/x', $this->calls[0]['url']);
    }

    public function testNon200Throws(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessageMatches('/403.*lacks scope/');
        $this->client($this->transport(403, '{"error":"API key lacks scope kv:fee_paid"}'))
             ->set('fee_paid', 'x', true);
    }

    public function testRequiresIdentityBaseAndApiKey(): void
    {
        $this->expectException(Exception::class);
        new KvClient('', 'k');
    }

    public function testRequiresApiKey(): void
    {
        $this->expectException(Exception::class);
        new KvClient('https://x', '');
    }
}
