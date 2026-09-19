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
    'service_name' => 'intranet',      // this app's slug: token aud must contain it; guest-role lookup
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

### Authorizing with policy (OPA)

Roles answer "who is this person"; policy answers "may they do *this* to *that*".
Policies are authored in solis-identity and shipped to an OPA sidecar as a bundle; this
library only asks the question. Mirrors `Solis::Session::PolicyClient` in the Ruby gem.

```php
$policy = new Solis\Session\PolicyClient('http://opa:8181', ['service_name' => 'dam']);

$claims = $session->authenticate();               // null for a guest
$d = $policy->authorize($claims, 'update', ['type' => 'asset', 'owner' => $asset->owner]);

if ($d->deny()) {
    http_response_code(403);
    exit($d->reason() ?? 'Forbidden');
}
```

Guest-mode services can ask without a token at all:

```php
$d = $policy->authorizeGuest('visitor', 'kadoc', 'read', ['type' => 'asset']);
```

**It fails closed.** An unreachable, slow or unparseable sidecar refuses the request — the
inverse of solis-lobby, which must fail open because it is a UX gate. `'fail' => 'open'`
exists for deployments that need it and logs a warning when constructed.

**OPA never sees the token.** `Session` has already validated it; this sends claim *values*
as plain JSON, never a credential.

`input.user` carries exactly the keys the Ruby gem sends, because policies generated by
solis-identity read them: `sub`, `email`, `tenant`, `tenants`, `authenticated`,
`tenant_member`, `roles`, `roles_by_application`, `groups`, `entitlements`, `scopes`.

- `roles` is platform roles plus **this** service's application roles, flattened.
- `roles_by_application` is the per-application map from the `app_roles` claim, for a rule
  that deliberately reaches into another application.
- The application asking is `input.context.service`, not a property of the user.

It has the same shape for a guest as for an authenticated user — `sub` null,
`authenticated` false, `tenant_member` false, `tenants` empty, and the guest role in
`roles` — so a rule reading `"visitor" in input.user.roles` needs no special case.

Note `tenant_member`: `input.user.tenant` is the workspace the *session* points at, not
proof of membership. Test the flag, not the slug.

A `Decision` exposes `allow()`, `reason()`, `denyLayers()`, `allowLayers()`, `filters()`,
`allowedFields()`, `deniedFields()` and `absentFields()`.

#### Listings: `filters()`

A listing cannot ask "may I read assets", so it asks with no resource and builds its query
from `$d->filters()`, a `Filters` object: `visible = OR(allow clauses) AND NOT OR(deny clauses)`.

```php
$f = $policy->authorize($claims, 'read')->filters();

if (!$f->isUsable()) {            // a restriction could not be expressed — do not list
    http_response_code(503);
    exit;
}
if ($f->isNone()) { /* nothing is visible: an empty listing is the correct answer */ }
$rows = $repo->where($f->allow(), $f->deny());
if (!$f->isComplete()) { /* some allow rule could not be expressed: say the list may be partial */ }
```

Absent, malformed and refused filters are **unusable**, never "unrestricted". An incomplete
*allow* side only costs rows; an incomplete *deny* side would list refused rows, so it makes
the whole set unusable.

### Managing user accounts

`UsersClient` covers the account lifecycle itself — create, update, suspend,
rename, remove — where `AttributesClient` reads and writes data *inside* an
account that already exists. The two are easy to confuse: this client cannot
touch attributes, and `AttributesClient` cannot create or delete a user.

Authorisation differs too. KV and attributes go by the key's **scopes**; here
what counts is the **role of the key's owning account**: `super_admin` or
`tenant_admin`. A `tenant_admin` key only reaches users holding a membership in
its own tenant and can never grant `super_admin`; `delete()` additionally
requires `super_admin`.

```php
use Solis\Session\UsersClient;

$users = new UsersClient('https://identity.example.com', getenv('SOLIS_USERS_API_KEY'));

$users->create('jane@example.com', 'Jane Doe');   // invited + welcome mail
$users->find('jane@example.com');                 // array, or null if no such account
$users->update('jane@example.com', ['name' => 'Jane R. Doe']);
$users->disable('jane@example.com');              // keeps everything; enable is a flip
$users->enable('jane@example.com');
$users->invite('jane@example.com');               // re-send the set-password mail
$users->changeEmail('jane@example.com', 'jane.doe@example.com');
$users->delete('jane@example.com');               // true (to trash, restorable)
```

`create()` without a `password` provisions the account as `invited` and identity
mails a set-password link, so the application never handles a password. Passing
one creates an already-active account. The name doubles as a login handle for
applications configured that way, so it must be unique platform-wide.

`update()` is a **partial** update: a call naming only `name` changes only the
name. It takes `name`, `roles`, `app_roles`, `api_keys_enabled` and `password`;
roles and app_roles apply to one membership (the key's own tenant, or `tenant`
for a super_admin), leaving other memberships alone. The address and the status
are not updatable there — `changeEmail()` also notifies the old address, and
`enable()`/`disable()` guard against locking yourself out, so sending those
fields throws rather than being silently ignored.

#### Password recovery

There is no `resetPassword()`, deliberately. The reset flow's token lifetime,
single-use guarantee, per-address and per-IP rate limits, and the neutral "if
that address exists we sent a mail" response all live on the identity server —
an application that drove it over an API would be reimplementing the parts that
make it safe. Point a "Forgot your password?" link at the tenant-scoped page
instead:

```php
$users->resetUrl('secretariat');
// => "https://identity.example.com/secretariat/auth/reset"
```

The tenant slug applies that tenant's branding to the page and the mail. There
is no `return_to` on this flow — the user comes back through the normal login
route afterwards. For the administrator-side case (a welcome link that expired
or never arrived), `invite()` re-sends it.

`find()` returns `null` for an unknown account (the server answers 404). Any
other non-200 throws `Solis\Session\Exception` with the HTTP status as the
exception code — `409` for a name or address already taken, `422` for invalid
input, `403` when the key's account lacks the role or the user is outside its
tenant.

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
- Audience: with `service_name` set, `aud` must contain it (array or string form);
  otherwise the request is treated as having no session. Without `service_name`,
  `aud` is not checked — set it in every service
- Key rotation: an unknown `kid` triggers one forced JWKS refresh before failing — at most once
  per 60 seconds, failed attempts included, so tokens with made-up kids cannot turn every request
  into a JWKS request to solis-identity (the same rule as the Ruby solis-session). The stamp is
  kept in the JWKS cache file, so **set `cache_dir`**: under PHP-FPM each request builds a new
  `Session`, and without a cache file the limit only holds within one request

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
OK (64 tests, 128 assertions)
```

No PHP on hand? The suite runs in a container with nothing else installed:

```bash
docker build -t solis-session-php . && docker run --rm solis-session-php
```

## License

MIT — see [LICENSE](LICENSE).
