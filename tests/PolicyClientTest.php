<?php

declare(strict_types=1);

namespace Solis\Session\Tests;

use PHPUnit\Framework\TestCase;
use Solis\Session\Claims;
use Solis\Session\Decision;
use Solis\Session\Exception;
use Solis\Session\Filters;
use Solis\Session\PolicyClient;

// PolicyClient is the PEP: it turns a request into OPA's `input` document and
// the answer into a Decision. The HTTP seam is injected so no sidecar is needed.
//
// These deliberately mirror test/policy_client_test.rb in the Ruby gem, test for
// test. A difference between the two would mean a policy means different things
// depending on which language the service happens to be written in.
final class PolicyClientTest extends TestCase
{
    /** @var array<int,array<string,mixed>> */
    private array $calls = [];

    /** @var array<int,string> */
    private array $logged = [];

    protected function setUp(): void
    {
        $this->calls  = [];
        $this->logged = [];
    }

    /** @param array<string,mixed> $result */
    private function transport(int $status = 200, ?array $result = null, ?string $raw = null): callable
    {
        $body = $raw ?? (string) json_encode(['result' => $result ?? ['allow' => true]]);
        return function (string $url, string $reqBody, int $timeoutMs) use ($status, $body) {
            $this->calls[] = [
                'url'       => $url,
                'body'      => json_decode($reqBody, true),
                'timeoutMs' => $timeoutMs,
            ];
            return [$status, $body];
        };
    }

    /** @param array<string,mixed> $options */
    private function client(callable $transport, array $options = []): PolicyClient
    {
        return new PolicyClient('http://opa:8181', array_merge([
            'transport'    => $transport,
            'service_name' => 'dam',
            'logger'       => function (string $m): void { $this->logged[] = $m; },
        ], $options));
    }

    private function claims(): Claims
    {
        return new Claims([
            'sub'           => 'jane@example.org',
            'email'         => 'jane@example.org',
            'tenant'        => 'kadoc',
            'tenants'       => ['kadoc', 'abv'],
            'application'   => 'dam',
            'tenant_member' => true,
            'groups'        => ['staff'],
            'roles'         => ['tenant_admin'],
            'app_roles'     => ['dam' => ['editor'], 'cms' => ['viewer']],
        ]);
    }

    /** @return array<string,mixed> */
    private function lastInput(): array
    {
        return $this->calls[count($this->calls) - 1]['body']['input'];
    }

    // ── The fixed entrypoint ─────────────────────────────────────────────

    public function testQueriesTheFixedDecisionPath(): void
    {
        $this->client($this->transport())->authorize($this->claims(), 'read');
        self::assertSame('http://opa:8181/v1/data/solis/decision/decision', $this->calls[0]['url']);
    }

    // ── Input document ───────────────────────────────────────────────────

    public function testInputCarriesTheValidatedClaims(): void
    {
        $this->client($this->transport())
             ->authorize($this->claims(), 'update', ['type' => 'asset', 'owner' => 'jane@example.org']);
        $input = $this->lastInput();

        self::assertSame('jane@example.org', $input['user']['sub']);
        self::assertSame('kadoc', $input['user']['tenant']);
        self::assertTrue($input['user']['authenticated']);
        self::assertTrue($input['user']['tenant_member']);
        self::assertSame('update', $input['action']);
        self::assertSame('asset', $input['resource']['type']);
    }

    // Which application is asking describes the request, not the person. It has
    // exactly one home, and a rule that reaches into input.user for it is reading
    // a key that is not there.
    public function testTheDecidingApplicationLivesInContextNotUser(): void
    {
        $this->client($this->transport())->authorize($this->claims(), 'read');
        $input = $this->lastInput();

        self::assertSame('dam', $input['context']['service']);
        self::assertArrayNotHasKey('application', $input['user'],
            'input.user.application duplicated input.context.service and is gone');
    }

    // `tenant` is the one workspace the session is looking through; `tenants` is
    // every workspace the subject belongs to. A cross-workspace rule needs both.
    public function testInputCarriesEveryWorkspaceTheSubjectBelongsTo(): void
    {
        $this->client($this->transport())->authorize($this->claims(), 'read');
        $user = $this->lastInput()['user'];

        self::assertSame('kadoc', $user['tenant']);
        self::assertSame(['kadoc', 'abv'], $user['tenants']);
    }

    // No token is forwarded. Session already validated it; policy sees claim
    // values, never a credential.
    public function testInputNeverCarriesAToken(): void
    {
        $this->client($this->transport())->authorize($this->claims(), 'read');
        self::assertStringNotContainsString(
            'Bearer',
            (string) json_encode($this->calls[0]['body'])
        );
    }

    public function testThisServicesAppRolesAreFlattenedIntoRoles(): void
    {
        $this->client($this->transport())->authorize($this->claims(), 'read');
        $roles = $this->lastInput()['user']['roles'];

        self::assertContains('editor', $roles, "this service's app_role must appear in roles");
        self::assertContains('tenant_admin', $roles, 'platform roles too');
        self::assertNotContains('viewer', $roles, "another app's roles must NOT be flattened in");
    }

    // The unflattened map is still there for a rule that deliberately reaches
    // into another application, under the name identity's generator reads.
    public function testRolesForOtherApplicationsAreStillAvailable(): void
    {
        $this->client($this->transport())->authorize($this->claims(), 'read');
        $user = $this->lastInput()['user'];

        self::assertSame(['viewer'], $user['roles_by_application']['cms']);
        self::assertArrayNotHasKey('app_roles', $user, 'renamed at the policy boundary');
    }

    // ── Filters ──────────────────────────────────────────────────────────
    //
    // A listing asks with no resource and reads these instead of `allow`. The
    // thing to get right is what happens when they are missing or partial: the
    // unsafe reading of "no filters" is "no restrictions".

    /** @return array<string,mixed> */
    private static function filtersFixture(array $overrides = []): array
    {
        return array_merge([
            'allow' => [['rule' => 'r5', 'terms' => [['field' => 'status', 'op' => 'eq', 'value' => 'published']]]],
            'deny'  => [['rule' => 'sys', 'terms' => [['field' => 'tenant', 'op' => 'neq', 'value' => 'kadoc']]]],
            'allow_complete' => true,
            'deny_complete'  => true,
        ], $overrides);
    }

    /** @param array<string,mixed> $result */
    private function decide(array $result): Decision
    {
        return $this->client($this->transport(200, $result))->authorize($this->claims(), 'read');
    }

    public function testFiltersAreParsedAsClausesNotPairs(): void
    {
        $f = $this->decide(['allow' => false, 'filters' => self::filtersFixture()])->filters();

        self::assertTrue($f->isUsable());
        self::assertTrue($f->isComplete());
        self::assertFalse($f->isNone());
        self::assertSame('r5', $f->allow()[0]['rule']);
        self::assertSame('status', $f->allow()[0]['terms'][0]['field']);
        self::assertCount(1, $f->deny());
    }

    // Flattening the object yields its values, which would read as clauses and
    // quietly produce a filter set nobody wrote.
    public function testAFiltersObjectNeverDegradesIntoAList(): void
    {
        $d = $this->decide(['allow' => false, 'filters' => self::filtersFixture()]);
        self::assertInstanceOf(Filters::class, $d->filters());
    }

    // An engine that does not send filters is not an engine that permits everything.
    public function testAbsentFiltersAreUnusableRatherThanUnrestricted(): void
    {
        $f = $this->decide(['allow' => true])->filters();
        self::assertFalse($f->isUsable());
        self::assertTrue($f->isNone());
    }

    public function testMalformedFiltersAreUnusable(): void
    {
        self::assertFalse($this->decide(['allow' => true, 'filters' => 'nonsense'])->filters()->isUsable());
    }

    // The asymmetry: a short list is a degraded listing, a long one is a leak.
    public function testAnIncompleteAllowIsStillUsable(): void
    {
        $f = $this->decide(['allow' => false, 'filters' => self::filtersFixture(['allow_complete' => false])])
                  ->filters();

        self::assertTrue($f->isUsable(), 'rows may be missing, which is safe');
        self::assertFalse($f->isComplete());
    }

    public function testAnIncompleteDenyIsNotUsable(): void
    {
        $f = $this->decide(['allow' => false, 'filters' => self::filtersFixture(['deny_complete' => false])])
                  ->filters();

        self::assertFalse($f->isUsable(), 'a restriction that could not be expressed would list refused rows');
    }

    // Distinct from unusable: the policy answered, and the answer is nothing.
    public function testNoAllowClausesIsAnEmptyListingNotABrokenOne(): void
    {
        $f = $this->decide(['allow' => false, 'filters' => self::filtersFixture(['allow' => []])])->filters();

        self::assertTrue($f->isUsable());
        self::assertTrue($f->isNone());
    }

    public function testARefusedDecisionCarriesNoUsableFilters(): void
    {
        self::assertFalse(Decision::refused('policy engine unreachable')->filters()->isUsable());
    }

    // PHP-specific: a deny side that is present but not a list must not read as
    // "no restrictions".
    public function testAMalformedDenySideIsNotUsable(): void
    {
        $f = $this->decide(['allow' => false, 'filters' => self::filtersFixture(['deny' => ['rule' => 'sys']])])
                  ->filters();

        self::assertFalse($f->isUsable());
    }

    // PHP-specific: json_decode turns {} into [], indistinguishable from the old
    // bare-array shape, so it resolves to unusable (Ruby reads {} as usable).
    public function testAnEmptyFiltersValueIsUnusable(): void
    {
        self::assertFalse($this->decide(['allow' => false, 'filters' => []])->filters()->isUsable());
    }

    // ── Guests ───────────────────────────────────────────────────────────

    // A guest has no token at all. The shape still has to be uniform, or every
    // policy needs a special case.
    public function testGuestInputIsAnonymousButUniform(): void
    {
        $this->client($this->transport())->authorizeGuest('visitor', 'kadoc', 'read');
        $user = $this->lastInput()['user'];

        self::assertNull($user['sub']);
        self::assertFalse($user['authenticated']);
        self::assertFalse($user['tenant_member'], 'a guest is never a member');
        self::assertSame('kadoc', $user['tenant']);
        self::assertSame([], $user['tenants'], 'a guest belongs to no workspace');
        self::assertSame(['visitor'], $user['roles']);
        self::assertSame(['dam' => ['visitor']], $user['roles_by_application']);
        self::assertArrayNotHasKey('application', $user);
    }

    // The point of the flattening: one rule serves both.
    public function testARoleRuleReadsTheSameForGuestAndAuthenticated(): void
    {
        $c = $this->client($this->transport());
        $c->authorizeGuest('visitor', 'kadoc', 'read');
        $c->authorize($this->claims(), 'read');

        self::assertContains('visitor', $this->calls[0]['body']['input']['user']['roles']);
        self::assertContains('editor', $this->calls[1]['body']['input']['user']['roles']);
    }

    // Authenticated and guest inputs must expose the same keys, or a rule written
    // for one is undefined for the other.
    public function testGuestAndAuthenticatedUserShapesHaveTheSameKeys(): void
    {
        $c = $this->client($this->transport());
        $c->authorizeGuest('visitor', 'kadoc', 'read');
        $c->authorize($this->claims(), 'read');

        $guestKeys  = array_keys($this->calls[0]['body']['input']['user']);
        $authedKeys = array_keys($this->calls[1]['body']['input']['user']);
        sort($guestKeys);
        sort($authedKeys);
        self::assertSame($authedKeys, $guestKeys);
    }

    // Pins the key set to the Ruby gem's build_input. A key added or renamed on one
    // side only is exactly the drift that made roles_by_application arrive as
    // app_roles here.
    public function testUserKeysMatchTheRubyContract(): void
    {
        $this->client($this->transport())->authorize($this->claims(), 'read');
        $keys = array_keys($this->lastInput()['user']);
        sort($keys);

        self::assertSame([
            'authenticated', 'email', 'entitlements', 'groups', 'roles',
            'roles_by_application', 'scopes', 'sub', 'tenant', 'tenant_member', 'tenants',
        ], $keys);
    }

    public function testNullClaimsProduceAGuestShape(): void
    {
        $this->client($this->transport())->authorize(null, 'read');
        self::assertFalse($this->lastInput()['user']['authenticated']);
    }

    // ── Decisions ────────────────────────────────────────────────────────

    public function testAllowAndDeny(): void
    {
        self::assertTrue(
            $this->client($this->transport(200, ['allow' => true]))
                 ->authorize($this->claims(), 'read')->allow()
        );

        $d = $this->client($this->transport(200, ['allow' => false, 'reason' => 'embargoed']))
                  ->authorize($this->claims(), 'read');
        self::assertTrue($d->deny());
        self::assertSame('embargoed', $d->reason());
    }

    public function testDecisionExposesLayersAndFieldLists(): void
    {
        $d = $this->client($this->transport(200, [
            'allow'         => false,
            'deny_layers'   => ['platform'],
            'allow_layers'  => ['application'],
            'denied_fields' => ['internal_notes'],
        ]))->authorize($this->claims(), 'read');

        self::assertSame(['platform'], $d->denyLayers(), 'a refusal must name the layer');
        self::assertSame(['application'], $d->allowLayers());
        self::assertSame(['internal_notes'], $d->deniedFields());
    }

    // Filters were once a bare array. The composition root sends an object with
    // its own completeness flags, and the old shape carries none of them — so it
    // is malformed rather than "a list of clauses with nothing restricting them".
    public function testTheOldBareArrayShapeIsTreatedAsMalformed(): void
    {
        $d = $this->client($this->transport(200, ['allow' => false, 'filters' => [['field' => 'status']]]))
                  ->authorize($this->claims(), 'read');

        self::assertFalse($d->filters()->isUsable());
    }

    // ── Fail closed ──────────────────────────────────────────────────────

    public function testUnreachableSidecarRefuses(): void
    {
        $boom = function (): array { throw new Exception('connection refused'); };
        $d = $this->client($boom)->authorize($this->claims(), 'read');

        self::assertTrue($d->deny(), 'an unreachable PDP must not let everyone in');
        self::assertSame(['unavailable'], $d->denyLayers(),
            'an outage must be distinguishable from a policy decision');
    }

    public function testNon200Refuses(): void
    {
        self::assertTrue(
            $this->client($this->transport(500))->authorize($this->claims(), 'read')->deny()
        );
    }

    public function testUnparseableBodyRefuses(): void
    {
        self::assertTrue(
            $this->client($this->transport(200, null, 'not json'))
                 ->authorize($this->claims(), 'read')->deny()
        );
    }

    // An undefined decision means the bundle did not load or the entrypoint is
    // missing. That is not "allowed".
    public function testMissingResultRefuses(): void
    {
        self::assertTrue(
            $this->client($this->transport(200, null, '{}'))
                 ->authorize($this->claims(), 'read')->deny()
        );
    }

    // ── Fail open, deliberately ──────────────────────────────────────────

    public function testFailOpenAllowsButSaysSo(): void
    {
        $boom = function (): array { throw new Exception('connection refused'); };
        $d = $this->client($boom, ['fail' => 'open'])->authorize($this->claims(), 'read');

        self::assertTrue($d->allow());
        self::assertSame(['fail_open'], $d->allowLayers());

        $joined = implode("\n", $this->logged);
        self::assertStringContainsString('fail=open', $joined,
            'choosing fail-open must leave a trace at construction');
    }

    public function testFailModeIsValidated(): void
    {
        $this->expectException(Exception::class);
        new PolicyClient('http://opa:8181', ['fail' => 'whatever']);
    }

    // ── Timeout and diagnostics ──────────────────────────────────────────

    public function testTimeoutIsPassedThrough(): void
    {
        $this->client($this->transport(), ['timeout_ms' => 250])->authorize($this->claims(), 'read');
        self::assertSame(250, $this->calls[0]['timeoutMs']);
    }

    public function testDefaultTimeoutIs100Ms(): void
    {
        $this->client($this->transport())->authorize($this->claims(), 'read');
        self::assertSame(100, $this->calls[0]['timeoutMs']);
    }

    // Schema drift: a resource field the policy references but the request did
    // not send makes that rule silently not fire — fail-open for a deny rule.
    public function testAbsentFieldsAreLogged(): void
    {
        $this->client($this->transport(200, ['allow' => true, 'absent_fields' => ['lifecycle_state']]))
             ->authorize($this->claims(), 'read');

        self::assertStringContainsString('lifecycle_state', implode("\n", $this->logged),
            'schema drift must be findable before it is an incident');
    }
}
