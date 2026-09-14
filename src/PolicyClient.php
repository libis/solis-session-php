<?php

declare(strict_types=1);

namespace Solis\Session;

/**
 * Asks an OPA sidecar whether the current request is allowed.
 *
 * The PHP counterpart of Solis::Session::PolicyClient. solis-identity authors
 * and ships the policy bundle, the sidecar evaluates it, and this turns a
 * request into the `input` document and the answer into a {@see Decision}.
 *
 *   $policy = new Solis\Session\PolicyClient('http://opa:8181');
 *   $d = $policy->authorize($claims, 'update', ['type' => 'asset', 'owner' => $a->owner]);
 *   if ($d->deny()) { http_response_code(403); exit($d->reason() ?? 'Forbidden'); }
 *
 * ── Two things worth knowing before you use it ────────────────────
 *
 * **OPA never sees the token.** Session has already validated it (RS256 over
 * JWKS, exp, aud). This sends claim *values* as plain JSON, never a credential.
 *
 * **It fails closed.** An unreachable, slow or unparseable sidecar refuses the
 * request. That is the exact inverse of solis-lobby, which must fail *open*
 * because it is a UX gate — a broken lobby must not lock anyone out. This is a
 * security control: a broken PDP must not let everyone in. `fail => 'open'`
 * exists for deployments that need it and emits a warning when constructed, so
 * choosing it leaves a trace.
 */
final class PolicyClient
{
    /**
     * The decision entrypoint is a fixed path, carrying no application slug.
     * It names the `decision` RULE, not the package: querying the package
     * returns every rule in it, including the composition root's internals.
     * Slugs are [a-z0-9_-] and `package solis.my-app` does not parse, so
     * sanitising one into the package would have to be reimplemented
     * identically here, in the Ruby client and in every OPA config. One bundle
     * carries one application, which is already the deployment model.
     */
    public const DECISION_PATH = '/v1/data/solis/decision/decision';

    public const DEFAULT_TIMEOUT_MS = 100;

    private string $url;
    private string $fail;
    private int $timeoutMs;
    private ?string $serviceName;

    /** @var callable(string,string,int):array{0:int,1:string}|null */
    private $transport;

    /** @var callable(string):void|null */
    private $logger;

    /**
     * @param array{
     *   fail?:string, timeout_ms?:int, service_name?:string,
     *   transport?:callable, logger?:callable
     * } $options
     *   transport is a test seam: fn(url, body, timeoutMs): [status, body]
     */
    public function __construct(string $opaUrl = 'http://opa:8181', array $options = [])
    {
        $this->url         = rtrim($opaUrl, '/') . self::DECISION_PATH;
        $this->fail        = $options['fail'] ?? 'closed';
        $this->timeoutMs   = (int) ($options['timeout_ms'] ?? self::DEFAULT_TIMEOUT_MS);
        $this->serviceName = $options['service_name'] ?? null;
        $this->transport   = $options['transport'] ?? null;
        $this->logger      = $options['logger'] ?? null;

        if ($this->fail !== 'closed' && $this->fail !== 'open') {
            throw new Exception("fail must be 'closed' or 'open', got: {$this->fail}");
        }
        if ($this->fail === 'open') {
            $this->warn(
                'solis-policy: fail=open — an unreachable OPA will ALLOW requests. '
                . 'This is a security control; closed is the default for a reason.'
            );
        }
    }

    /**
     * @param Claims|null          $claims   null for a guest (no token at all)
     * @param array<string,mixed>  $resource whatever this service sends
     * @param array<string,mixed>  $context
     */
    public function authorize(
        ?Claims $claims,
        string $action,
        array $resource = [],
        array $context = []
    ): Decision {
        return $this->query($this->buildInput($claims, $action, $resource, $context));
    }

    /**
     * Convenience for a guest-mode service: the app's guest role, no token.
     *
     * @param array<string,mixed> $resource
     */
    public function authorizeGuest(
        string $guestRole,
        string $tenant,
        string $action,
        array $resource = []
    ): Decision {
        return $this->query($this->guestInput($guestRole, $tenant, $action, $resource));
    }

    /**
     * The `input` document. Public because it is the contract with the policy
     * author — a rule can only reference what appears here.
     *
     * @param array<string,mixed> $resource
     * @param array<string,mixed> $context
     * @return array<string,mixed>
     */
    public function buildInput(
        ?Claims $claims,
        string $action,
        array $resource = [],
        array $context = []
    ): array {
        if ($claims === null) {
            return $this->guestInput('', '', $action, $resource, $context);
        }

        $service = $this->serviceName ?? $claims->application();
        $all     = $claims->all();

        // The key set of `user` below is the contract with every generated rule and
        // must stay identical to Solis::Session::PolicyClient#build_input. Which
        // application is asking is deliberately NOT here: it describes the request,
        // not the person, and lives in context.service.
        return [
            'user' => [
                'sub'           => $claims->subject(),
                'email'         => $claims->email(),
                // The workspace this decision is happening in.
                'tenant'        => $claims->tenant(),
                // Every workspace the subject belongs to, not just the active one,
                // so a rule can ask "is this in a workspace they are in at all".
                'tenants'       => $claims->tenants(),
                // Set by the PEP, not a token claim: policy must never have to
                // infer "signed in" from a null sub.
                'authenticated' => true,
                // Membership in the ACTIVE tenant, which `tenant` does NOT imply
                // — an app-scoped login takes the tenant from the URL, so a user
                // whose only membership is elsewhere still gets a token naming
                // this workspace.
                'tenant_member' => ($all['tenant_member'] ?? false) === true,
                // Platform roles plus THIS service's app_roles, flattened, so a
                // rule reads the same for a guest and an authenticated user.
                'roles'         => $this->effectiveRoles($claims, $service),
                // Roles per application within the active tenant, from the
                // `app_roles` claim. Renamed at the policy boundary: identity's
                // generator reads input.user.roles_by_application, so under the old
                // name a rule reaching into another application silently never
                // fired — which for a deny rule is fail-open.
                'roles_by_application' => $all['app_roles'] ?? [],
                'groups'        => $claims->groups(),
                'entitlements'  => array_values((array) ($all['entitlements'] ?? [])),
                'scopes'        => array_values((array) ($all['scopes'] ?? [])),
            ],
            'action'   => $action,
            'resource' => $resource,
            'request'  => [
                'method' => $_SERVER['REQUEST_METHOD'] ?? null,
                'path'   => parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/',
            ],
            'context' => array_merge([
                'now'     => gmdate('c'),
                'service' => $service,
            ], $context),
        ];
    }

    /**
     * @param array<string,mixed> $resource
     * @param array<string,mixed> $context
     * @return array<string,mixed>
     */
    private function guestInput(
        string $guestRole,
        string $tenant,
        string $action,
        array $resource = [],
        array $context = []
    ): array {
        $service = $this->serviceName ?? '';
        $roles   = $guestRole === '' ? [] : [$guestRole];

        return [
            'user' => [
                'sub'           => null,
                'email'         => null,
                'tenant'        => $tenant,
                'tenants'       => [],      // a guest belongs to no workspace
                'authenticated' => false,
                'tenant_member' => false,   // a guest is never a member
                'roles'         => $roles,
                'roles_by_application' => $service === '' ? [] : [$service => $roles],
                'groups'        => [],
                'entitlements'  => [],
                'scopes'        => [],
            ],
            'action'   => $action,
            'resource' => $resource,
            'request'  => [
                'method' => $_SERVER['REQUEST_METHOD'] ?? null,
                'path'   => parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/',
            ],
            'context' => array_merge([
                'now'     => gmdate('c'),
                'service' => $service,
            ], $context),
        ];
    }

    /** @return array<int,string> */
    private function effectiveRoles(Claims $claims, string $service): array
    {
        $mine = $service === '' ? [] : $claims->appRoles($service);
        return array_values(array_unique(array_merge($claims->roles(), $mine)));
    }

    /** @param array<string,mixed> $input */
    private function query(array $input): Decision
    {
        try {
            [$status, $body] = $this->send((string) json_encode(['input' => $input]));
        } catch (\Throwable $e) {
            return $this->refuse('policy engine unreachable: ' . $e->getMessage());
        }

        if ($status !== 200) {
            return $this->refuse("policy engine returned HTTP $status");
        }

        $parsed = json_decode($body, true);
        if (!is_array($parsed)) {
            return $this->refuse('policy engine returned unparseable JSON');
        }

        // An undefined decision means the bundle did not load or the entrypoint
        // is missing — not "allowed".
        $result = $parsed['result'] ?? null;
        if (!is_array($result)) {
            return $this->refuse('policy engine returned no decision');
        }

        $decision = Decision::from($result);
        $absent   = $decision->absentFields();
        if ($absent !== []) {
            $this->warn(
                'solis-policy: policy references resource fields not sent: '
                . implode(', ', $absent)
            );
        }
        return $decision;
    }

    /** @return array{0:int,1:string} */
    private function send(string $body): array
    {
        if ($this->transport !== null) {
            return ($this->transport)($this->url, $body, $this->timeoutMs);
        }

        $ch = curl_init($this->url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST  => 'POST',
            CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_TIMEOUT_MS     => $this->timeoutMs,
            CURLOPT_CONNECTTIMEOUT_MS => $this->timeoutMs,
        ]);
        $resp = curl_exec($ch);
        if ($resp === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new Exception("Policy request failed: $err");
        }
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return [$status, (string) $resp];
    }

    private function refuse(string $message): Decision
    {
        $this->warn('solis-policy: ' . $message . ' — '
            . ($this->fail === 'open' ? 'ALLOWING' : 'refusing'));

        if ($this->fail === 'open') {
            return new Decision([
                'allow'        => true,
                'reason'       => $message,
                'allow_layers' => ['fail_open'],
            ]);
        }
        return Decision::refused($message);
    }

    private function warn(string $message): void
    {
        if ($this->logger !== null) {
            ($this->logger)($message);
            return;
        }
        error_log($message);
    }
}
