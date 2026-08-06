<?php

declare(strict_types=1);

namespace Solis\Session;

/**
 * PHP counterpart of the Ruby solis-session middleware. Validates the shared
 * `solis_session` RS256 JWT (from the cookie or a Bearer header) against
 * solis-identity's JWKS and exposes the claims. Where every app lives under
 * one registrable domain, the cookie is already present on each request —
 * this class only has to verify it, never mint anything.
 *
 * Typical use in a front controller / Grav plugin:
 *
 *   $session = Solis\Session\Session::fromIdentityBase('https://identity.example.com', [
 *       'service_name' => 'intranet',
 *       'cache_dir'    => sys_get_temp_dir(),
 *   ]);
 *   $claims = $session->authenticate();          // Claims or null
 *   if ($claims === null) {
 *       $session->requireLogin();                // 401 (XHR/JSON) or 302 to login
 *   }
 *   if (!$claims->hasAppRole('intranet', 'content-editor')) { http_response_code(403); }
 */
final class Session
{
    public const COOKIE_NAME = 'solis_session';

    private Jwks $jwks;
    private string $identityBase;
    private string $mountpoint;
    private ?string $serviceName;
    private int $leeway;

    /** @var callable(string):string|null */
    private $fetcher;

    private ?Claims $claims = null;
    private bool $evaluated = false;

    /**
     * @param array{
     *   mountpoint?:string, service_name?:string, jwks_ttl?:int,
     *   cache_dir?:string, leeway?:int, fetcher?:callable, jwks?:Jwks
     * } $options
     */
    public function __construct(string $identityBase, array $options = [])
    {
        $this->identityBase = rtrim($identityBase, '/');
        // No mountpoint by default — solis-identity at the root of its own
        // host is the common case. Deployments that mount it under a path pass
        // e.g. 'mountpoint' => '_'. Normalised the same way as KvClient: an
        // empty value contributes nothing rather than a stray '/'.
        $mp = trim((string) ($options['mountpoint'] ?? ''), '/');
        $this->mountpoint = $mp === '' ? '' : '/' . $mp;
        $this->serviceName = $options['service_name'] ?? null;
        $this->leeway = (int) ($options['leeway'] ?? 60);
        $this->fetcher = $options['fetcher'] ?? null;

        if (isset($options['jwks']) && $options['jwks'] instanceof Jwks) {
            $this->jwks = $options['jwks'];
        } else {
            $cacheFile = isset($options['cache_dir'])
                ? rtrim((string) $options['cache_dir'], '/') . '/solis_jwks_' . md5($this->jwksUrl()) . '.json'
                : null;
            $this->jwks = new Jwks($this->jwksUrl(), (int) ($options['jwks_ttl'] ?? 3600), $cacheFile, $this->fetcher);
        }
    }

    /** Convenience factory mirroring the option names above. */
    public static function fromIdentityBase(string $identityBase, array $options = []): self
    {
        return new self($identityBase, $options);
    }

    /**
     * Verifies the request's token and returns its Claims, or null when no
     * valid token is present. Never throws for the "not logged in" case —
     * verification failures are treated as "no session".
     */
    public function authenticate(): ?Claims
    {
        if ($this->evaluated) {
            return $this->claims;
        }
        $this->evaluated = true;
        $token = $this->extractToken();
        if ($token === null) {
            return $this->claims = null;
        }
        try {
            $payload = Jwt::verify($token, $this->jwks, $this->leeway);
            return $this->claims = new Claims($payload);
        } catch (Exception) {
            return $this->claims = null;
        }
    }

    /** True when a valid session is present. */
    public function isAuthenticated(): bool
    {
        return $this->authenticate() !== null;
    }

    public function claims(): ?Claims
    {
        return $this->authenticate();
    }

    /**
     * Ends the request for an unauthenticated caller the way the Ruby
     * middleware does: 401 JSON for XHR/JSON clients, else a 302 redirect to
     * the tenant login with return_to set to the current URL. Does not return
     * unless $exit is false (useful in tests).
     */
    public function requireLogin(?string $tenant = null, bool $exit = true): void
    {
        if ($this->isXhrOrJson()) {
            http_response_code(401);
            header('Content-Type: application/json');
            echo '{"error":"Unauthorized"}';
        } else {
            http_response_code(302);
            header('Location: ' . $this->loginUrl($tenant));
        }
        if ($exit) {
            exit;
        }
    }

    /**
     * Requires the session to hold at least one of $roles (tenant roles);
     * super_admin always passes. Sends 401 (no session) or 403 (insufficient)
     * and stops, unless $exit is false.
     */
    public function requireRole(array $roles, bool $exit = true): bool
    {
        $claims = $this->authenticate();
        if ($claims === null) {
            $this->requireLogin(null, $exit);
            return false;
        }
        if ($claims->isSuperAdmin()) {
            return true;
        }
        foreach ($roles as $role) {
            if ($claims->hasRole((string) $role)) {
                return true;
            }
        }
        http_response_code(403);
        if ($exit) {
            exit;
        }
        return false;
    }

    /**
     * The login URL to redirect an unauthenticated browser to. Uses the tenant
     * from the (expired) claims when available, else $tenant, else 'system'.
     * return_to is the current absolute URL so the user lands back here.
     */
    public function loginUrl(?string $tenant = null): string
    {
        $slug = $tenant ?: ($this->claims?->tenant() ?: 'system');
        $returnTo = $this->currentUrl();
        return $this->identityBase . $this->mountpoint . '/' . rawurlencode($slug) . '/login'
            . '?return_to=' . rawurlencode($returnTo);
    }

    /**
     * The guest role solis-identity advertises for this service in its OIDC
     * discovery document (app_guest_roles[service_name]). Returns null when the
     * service requires login or identity is unreachable — matching the Ruby
     * middleware's fail-open-to-no-guest behavior.
     */
    public function guestRole(): ?string
    {
        if ($this->serviceName === null) {
            return null;
        }
        try {
            $body = $this->fetch($this->identityBase . $this->mountpoint . '/.well-known/openid-configuration');
            $doc = json_decode($body, true);
            $role = $doc['app_guest_roles'][$this->serviceName] ?? null;
            $role = is_string($role) ? trim($role) : '';
            return $role === '' ? null : $role;
        } catch (\Throwable) {
            return null;
        }
    }

    // ── Internals ───────────────────────────────────────────────────────────

    private function extractToken(): ?string
    {
        if (!empty($_COOKIE[self::COOKIE_NAME])) {
            return (string) $_COOKIE[self::COOKIE_NAME];
        }
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (preg_match('/\ABearer\s+(.+)\z/i', (string) $auth, $m)) {
            return trim($m[1]);
        }
        return null;
    }

    private function jwksUrl(): string
    {
        return $this->identityBase . $this->mountpoint . '/.well-known/jwks.json';
    }

    private function isXhrOrJson(): bool
    {
        $xrw = strtolower((string) ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? ''));
        if ($xrw === 'xmlhttprequest') {
            return true;
        }
        $accept = (string) ($_SERVER['HTTP_ACCEPT'] ?? '');
        return str_contains($accept, 'application/json') && !str_contains($accept, 'text/html');
    }

    private function currentUrl(): string
    {
        $https = (($_SERVER['HTTPS'] ?? '') !== '' && ($_SERVER['HTTPS'] ?? 'off') !== 'off')
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
        $scheme = $https ? 'https' : 'http';
        $host = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        return $scheme . '://' . $host . $uri;
    }

    private function fetch(string $url): string
    {
        if ($this->fetcher !== null) {
            return ($this->fetcher)($url);
        }
        $ctx = stream_context_create(['http' => ['timeout' => 5], 'https' => ['timeout' => 5]]);
        $body = @file_get_contents($url, false, $ctx);
        if ($body === false) {
            throw new Exception('Unable to fetch ' . $url);
        }
        return $body;
    }
}
