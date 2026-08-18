<?php

declare(strict_types=1);

namespace Solis\Session\Tests;

use PHPUnit\Framework\TestCase;
use Solis\Session\Exception;
use Solis\Session\UsersClient;

// UsersClient drives the account lifecycle on solis-identity (/api/users) —
// create, update, enable/disable, rename, delete. The HTTP seam is injected
// (transport) so no real request / running identity is needed.
final class UsersClientTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $calls = [];

    private function transport(int $status = 200, ?string $body = null): callable
    {
        $body ??= json_encode(['email' => 'jane@example.com', 'status' => 'active']);
        return function (string $method, string $url, array $headers, ?string $reqBody) use ($status, $body) {
            $this->calls[] = compact('method', 'url', 'headers', 'reqBody');
            return [$status, $body];
        };
    }

    private function client(callable $transport, array $opts = []): UsersClient
    {
        return new UsersClient(
            'https://identity.example.com',
            'raw-key',
            array_merge(['transport' => $transport], $opts)
        );
    }

    /** @return array<string,mixed> */
    private function sentBody(int $i = 0): array
    {
        return json_decode($this->calls[$i]['reqBody'], true);
    }

    // ── Construction ─────────────────────────────────────────────────────────

    public function testRequiresIdentityBase(): void
    {
        $this->expectException(Exception::class);
        new UsersClient('', 'raw-key');
    }

    public function testRequiresApiKey(): void
    {
        $this->expectException(Exception::class);
        new UsersClient('https://identity.example.com', '  ');
    }

    public function testMountpointIsApplied(): void
    {
        $this->client($this->transport())->find('jane@example.com');
        $this->assertSame(
            'https://identity.example.com/api/users/jane%40example.com',
            $this->calls[0]['url']
        );

        $this->calls = [];
        $this->client($this->transport(), ['mountpoint' => '_'])->find('jane@example.com');
        $this->assertSame(
            'https://identity.example.com/_/api/users/jane%40example.com',
            $this->calls[0]['url']
        );
    }

    public function testAuthenticatesWithTheApiKey(): void
    {
        $this->client($this->transport())->find('jane@example.com');
        $this->assertContains('Authorization: ApiKey raw-key', $this->calls[0]['headers']);
    }

    // ── Read ─────────────────────────────────────────────────────────────────

    public function testFindReturnsTheUser(): void
    {
        $user = $this->client($this->transport(200, json_encode([
            'email' => 'jane@example.com', 'name' => 'Jane', 'status' => 'active',
        ])))->find('jane@example.com');

        $this->assertSame('GET', $this->calls[0]['method']);
        $this->assertSame('Jane', $user['name']);
    }

    // "No such account" is a normal answer, not an error.
    public function testFindReturnsNullOnUnknownUser(): void
    {
        $client = $this->client($this->transport(404, json_encode(['error' => 'not_found'])));
        $this->assertNull($client->find('nobody@example.com'));
    }

    public function testFindStillThrowsOnOtherErrors(): void
    {
        $client = $this->client($this->transport(403, json_encode(['error' => 'forbidden'])));
        $this->expectException(Exception::class);
        $client->find('outside@example.com');
    }

    // ── Create ───────────────────────────────────────────────────────────────

    public function testCreatePostsEmailAndName(): void
    {
        $this->client($this->transport(201, json_encode([
            'email' => 'jane@example.com', 'status' => 'invited', 'invitation_sent' => true,
        ])))->create('jane@example.com', 'Jane Doe');

        $this->assertSame('POST', $this->calls[0]['method']);
        $this->assertSame('https://identity.example.com/api/users', $this->calls[0]['url']);
        $this->assertSame(['email' => 'jane@example.com', 'name' => 'Jane Doe'], $this->sentBody());
        $this->assertContains('Content-Type: application/json', $this->calls[0]['headers']);
    }

    public function testCreateMergesExtraFields(): void
    {
        $this->client($this->transport(201))->create('jane@example.com', 'Jane Doe', [
            'roles'     => ['user'],
            'app_roles' => ['members' => ['content-editor']],
        ]);
        $body = $this->sentBody();
        $this->assertSame(['user'], $body['roles']);
        $this->assertSame(['content-editor'], $body['app_roles']['members']);
    }

    // The address and name are the client's own arguments, so a stray 'email'
    // in $fields must not be able to redirect the call.
    public function testCreateFieldsCannotOverrideEmailOrName(): void
    {
        $this->client($this->transport(201))->create('jane@example.com', 'Jane Doe', [
            'email' => 'attacker@example.com',
            'name'  => 'Someone Else',
        ]);
        $body = $this->sentBody();
        $this->assertSame('jane@example.com', $body['email']);
        $this->assertSame('Jane Doe', $body['name']);
    }

    // Create answers 201, not 200 — anything else is a failure.
    public function testCreateRequires201(): void
    {
        $client = $this->client($this->transport(200));
        $this->expectException(Exception::class);
        $client->create('jane@example.com', 'Jane Doe');
    }

    public function testCreateSurfacesTheConflictStatus(): void
    {
        $client = $this->client($this->transport(409, json_encode(['error' => 'conflict'])));
        try {
            $client->create('taken@example.com', 'Taken');
            $this->fail('expected a conflict');
        } catch (Exception $e) {
            $this->assertSame(409, $e->getCode());
        }
    }

    // ── Update ───────────────────────────────────────────────────────────────

    public function testUpdatePatchesOnlyWhatItIsGiven(): void
    {
        $this->client($this->transport())->update('jane@example.com', ['name' => 'Jane R. Doe']);

        $this->assertSame('PATCH', $this->calls[0]['method']);
        $this->assertSame(
            'https://identity.example.com/api/users/jane%40example.com',
            $this->calls[0]['url']
        );
        $this->assertSame(['name' => 'Jane R. Doe'], $this->sentBody());
    }

    public function testUpdateSurfacesTheRefusalStatus(): void
    {
        $client = $this->client($this->transport(422, json_encode([
            'error' => 'invalid', 'message' => 'Use POST /api/users/:email/enable or /disable',
        ])));
        try {
            $client->update('jane@example.com', ['status' => 'disabled']);
            $this->fail('expected a refusal');
        } catch (Exception $e) {
            $this->assertSame(422, $e->getCode());
        }
    }

    // ── Status, rename, invite, delete ───────────────────────────────────────

    public function testEnableAndDisable(): void
    {
        $client = $this->client($this->transport());
        $client->disable('jane@example.com');
        $client->enable('jane@example.com');

        $this->assertSame('POST', $this->calls[0]['method']);
        $this->assertStringEndsWith('/jane%40example.com/disable', $this->calls[0]['url']);
        $this->assertStringEndsWith('/jane%40example.com/enable', $this->calls[1]['url']);
        $this->assertNull($this->calls[0]['reqBody']);
    }

    public function testChangeEmailSendsNewEmail(): void
    {
        $this->client($this->transport())->changeEmail('jane@example.com', 'jane.doe@example.com');
        $this->assertStringEndsWith('/jane%40example.com/change-email', $this->calls[0]['url']);
        $this->assertSame(['new_email' => 'jane.doe@example.com'], $this->sentBody());
    }

    public function testInvite(): void
    {
        $this->client($this->transport(200, json_encode(['invitation_sent' => true])))
             ->invite('jane@example.com');
        $this->assertStringEndsWith('/jane%40example.com/invite', $this->calls[0]['url']);
    }

    public function testDeleteReportsWhetherItHappened(): void
    {
        $client = $this->client($this->transport(200, json_encode(['deleted' => true])));
        $this->assertTrue($client->delete('jane@example.com'));
        $this->assertSame('DELETE', $this->calls[0]['method']);
    }

    // ── Password recovery ────────────────────────────────────────────────────

    public function testResetUrlIsTenantScopedAndMakesNoRequest(): void
    {
        $client = $this->client($this->transport(), ['mountpoint' => '_']);
        $this->assertSame(
            'https://identity.example.com/_/secretariat/auth/reset',
            $client->resetUrl('secretariat')
        );
        $this->assertSame([], $this->calls, 'building the link must not call identity');
    }
}
