# solis-session-php

PHP client for solis-identity. The PHP counterpart of the
Ruby `solis-session` middleware: it validates the shared `solis_session`
RS256 JWT (from the cookie or a `Bearer` header) against solis-identity's JWKS
and exposes the claims as typed accessors.

Intended for deployments where every app lives under one registrable domain
(`*.example.com`), so the `solis_session` cookie is already present on each
request — this library only has to **verify** it, never mint anything.

## Why no dependencies

RS256 verification and the JWK→PEM reconstruction are implemented directly on
PHP's built-in `ext-openssl`, so the package has **zero runtime Composer
dependencies**. It works the moment the files are on disk — no `composer
install` needed in production. `firebase/php-jwt` is deliberately *not* used;
the algorithm is pinned to RS256 and never read from the token header, so
`alg:none` / HS256 confusion attacks don't apply.

## Install

```bash
composer require solis/session-php
# or vendor the src/ directory directly and use tests/bootstrap.php's PSR-4 fallback
```

Requires PHP ≥ 8.1 with `ext-openssl` and `ext-json` (both standard).

## Usage

```php
use Solis\Session\Session;

$session = Session::fromIdentityBase('https://identity.example.com', [
    'service_name' => 'intranet',      // this app's slug (for guest-role lookup)
    'mountpoint'   => '',              // only if identity is under a path, e.g. '_'
    'cache_dir'    => sys_get_temp_dir(), // JWKS on-disk cache (optional)
    'jwks_ttl'     => 3600,            // JWKS cache lifetime, seconds
]);

$claims = $session->authenticate();    // Solis\Session\Claims, or null

if ($claims === null) {
    // 401 for XHR/JSON, else 302 → https://identity.example.com/<tenant>/login?return_to=…
    $session->requireLogin();
}

// Tenant-level gate (super_admin always passes):
$session->requireRole(['tenant_admin']);

// Per-application working-group authorization:
if (!$claims->hasAppRole('intranet', 'content-editor')) {
    http_response_code(403);
    exit;
}

// Membership/fee status projected by the registry via the :kv resolver:
if (!$claims->feePaid()) { /* soft-lock member-only content */ }
```

### Claims accessors

| Method | Returns |
| --- | --- |
| `subject()`, `email()`, `name()` | identity basics |
| `tenant()`, `application()` | active tenant / app slugs |
| `roles()`, `hasRole($r)`, `isSuperAdmin()` | tenant roles |
| `appRoles($app)`, `hasAppRole($app,$r)` | per-application roles (working groups) |
| `groups()` | groups claim |
| `feePaid()` | registry `fee_paid` projection (absent → false) |
| `get($key, $default)`, `all()` | raw claim access |

### Writing to the KV claim store

Reading KV values needs no client — they arrive as JWT claims (via the identity
server's `:kv` resolver) and are exposed by `Claims` (e.g. `$claims->feePaid()`).
To *write* a value (e.g. a membership app pushing fee status), use `KvClient`.
It authenticates with a scoped SOLIS **API key** (scope `kv:<namespace>` or
`kv:*`), not the session cookie — a KV push is a privileged operation at a
different trust level than a user session.

```php
use Solis\Session\KvClient;

$kv = new KvClient('https://identity.example.com', getenv('SOLIS_KV_API_KEY'));

$kv->set('fee_paid', 'acme', true);      // ['ok' => true, ...]
$kv->delete('fee_paid', 'acme');         // ['ok' => true, 'deleted' => true]
```

A non-200 throws `Solis\Session\Exception` with the status and body (401 bad
key, 403 wrong scope, 400 bad value/component). There is deliberately no `get()`
— the KV is a projection, not a query API; reads come back as token claims.

### Reading and writing user attributes

Attributes are the counterpart to KV, and the difference is what reaches a
token. A KV value is projected into the JWT at issuance, so you write it here
and read it back off `Claims`. An attribute **never enters a token at all** — so
`AttributesClient` reads as well as writes, and a value can change without
anyone reissuing a session.

Use attributes for what an app wants to *know* about a person (preferences,
profile extras, an external record id); use KV for what the platform needs to
*decide* with (entitlements that gate access).

```php
use Solis\Session\AttributesClient;

$attrs = new AttributesClient('https://identity.example.com', getenv('SOLIS_ATTRS_API_KEY'));

$attrs->all('jane@example.com');                 // ['orcid' => '0000-…']
$attrs->get('jane@example.com', 'orcid');        // '0000-…'  (null if absent)
$attrs->set('jane@example.com', 'seats', 5);
$attrs->merge('jane@example.com', ['a' => 1, 'b' => null]);   // null deletes 'b'
$attrs->replace('jane@example.com', ['only' => 'this']);      // replaces the hash
$attrs->delete('jane@example.com', 'seats');
$attrs->clear('jane@example.com');
```

In a request the email comes off the validated session, so the common call is:

```php
$attrs->forClaims($session->claims());   // [] when there is no session
```

Scopes are `attributes:read`, `attributes:write`, or `attributes:*`; a write
scope implies read. The key's own account bounds its reach — unless it belongs
to a super_admin, it only sees users in its owner's workspace.

`get()` returns `null` for a key that is not set (the server answers 404, which
keeps "not set" distinct from "set to null" — use `all()` and
`array_key_exists()` when you need to tell them apart). Any other non-200 throws
`Solis\Session\Exception`, with the HTTP status as the exception code.

### Grav

The Grav plugin is a thin wrapper: on each request build a `Session`, map
`app_roles['<app-slug>']` → Grav groups and `feePaid()` → a member group,
record `tenant()` on the Grav account, and call `requireLogin()` for protected
page trees. Page-tree ACLs then use the mapped Grav groups.

## Contract (mirrors the Ruby middleware)

- Cookie name: `solis_session`
- JWKS: `<identityBase><mountpoint>/.well-known/jwks.json` — the mountpoint is
  optional and empty by default (identity at the root of its own host); set it
  only where solis-identity is mounted under a path
- Guest role: `app_guest_roles[service_name]` in
  `<identityBase><mountpoint>/.well-known/openid-configuration` (fail-open to
  no-guest when identity is unreachable)
- Signature: RS256 only; `exp`/`nbf`/`iat` enforced with 60 s leeway
- Key rotation: an unknown `kid` triggers one forced JWKS refresh before failing

## Testing

```bash
composer install
composer test
```

The fixtures in `tests/fixtures/` mirror the **exact** JWKS shape and RS256
signing solis-identity's `JwtIssuer` emits — same header key order, same JWK
member order, same unpadded base64url — so a green suite exercises the verifier
against the wire format it meets in production. The claims are fictional and
the signing keys are generated and discarded per run; only public halves are
committed. Regenerate:

```bash
php tests/fixtures/generate.php
```

Regenerating produces new RSA keys, so `jwks.json` and all three tokens change
together — commit them as a set.

Runs clean on PHP 8.2:

```
OK (20 tests, 41 assertions)
```

No PHP on hand? The suite runs in a container with nothing else installed:

```bash
docker build -t solis-session-php . && docker run --rm solis-session-php
```

## License

MIT — see [LICENSE](LICENSE).
