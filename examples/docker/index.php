<?php

declare(strict_types=1);

/**
 * Interactive check of solis-session-php against a running solis-identity.
 *
 * Deliberately uses no Composer autoloader — the package's own PSR-4 fallback
 * is enough, which is the zero-runtime-dependency claim in practice.
 *
 * Two base URLs, because the browser and this container reach solis-identity by
 * different names when it runs on the host:
 *
 *   SOLIS_IDENTITY_BASE      what the BROWSER uses  (http://localhost:4567)
 *   SOLIS_IDENTITY_INTERNAL  what THIS PROCESS uses (http://host.docker.internal:4567)
 *
 * The library's `fetcher` option exists for exactly this: server-side calls
 * (JWKS, discovery) go through it, while redirect URLs keep the browser-facing
 * host. Leave SOLIS_IDENTITY_INTERNAL unset when both are the same.
 */

require __DIR__ . '/../src/Session.php';
require __DIR__ . '/../src/Claims.php';
require __DIR__ . '/../src/Jwks.php';
require __DIR__ . '/../src/Jwt.php';
require __DIR__ . '/../src/Exception.php';

use Solis\Session\Session;

$base     = rtrim(getenv('SOLIS_IDENTITY_BASE') ?: 'http://localhost:4567', '/');
$internal = rtrim(getenv('SOLIS_IDENTITY_INTERNAL') ?: $base, '/');
// An unset variable and an empty one mean different things: solis-identity's
// :mountpoint may legitimately be "" (everything served from the root), so an
// explicit empty value is passed through rather than defaulted away.
$mountEnv = getenv('SOLIS_MOUNTPOINT');
$mount    = $mountEnv === false ? '' : $mountEnv;
$tenant   = getenv('SOLIS_TENANT') ?: 'system';
$app      = getenv('SOLIS_APP') ?: null;

// What the library will actually use: an empty mountpoint contributes no path
// segment at all, so identity served from the root of its host needs no
// configuration here. Shown so the effective value is never a guess.
$normalisedMount = ($m = trim($mount, '/')) === '' ? '' : '/' . $m;

$options = ['mountpoint' => $mount];
if ($app !== null) {
    $options['service_name'] = $app;
}
if ($internal !== $base) {
    // Rewrite only the origin; the path is whatever the library asked for.
    $options['fetcher'] = static function (string $url) use ($base, $internal): string {
        $target = str_starts_with($url, $base) ? $internal . substr($url, strlen($base)) : $url;
        $ctx    = stream_context_create(['http' => ['timeout' => 5], 'https' => ['timeout' => 5]]);
        $body   = @file_get_contents($target, false, $ctx);
        if ($body === false) {
            throw new \RuntimeException('could not reach ' . $target);
        }
        return $body;
    };
}

$session = Session::fromIdentityBase($base, $options);

$error  = null;
$claims = null;
try {
    $claims = $session->authenticate();
} catch (\Throwable $e) {
    $error = $e->getMessage();
}

// Logging in is an explicit click, not an automatic redirect — the point of the
// page is to show what the URL would be before following it.
if (isset($_GET['login'])) {
    header('Location: ' . $session->loginUrl($tenant));
    exit;
}

$tenantLoginUrl = $session->loginUrl($tenant);
$appLoginUrl    = $app === null ? null
    : $base . $normalisedMount . '/' . rawurlencode($tenant) . '/' . rawurlencode($app) . '/login'
      . '?return_to=' . rawurlencode(currentUrl());

function currentUrl(): string
{
    $https = ($_SERVER['HTTPS'] ?? '') === 'on';
    return ($https ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? 'localhost')
        . ($_SERVER['REQUEST_URI'] ?? '/');
}

function h(?string $s): string
{
    return htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
}

?><!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>solis-session-php demo</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 52rem; padding: 0 1rem; }
  code, pre { font-family: ui-monospace, monospace; font-size: 13px; }
  pre { background: #f6f8fa; padding: .75rem; border-radius: 6px; overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; margin: .5rem 0 1.5rem; }
  th, td { text-align: left; padding: .35rem .5rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }
  th { width: 14rem; color: #555; font-weight: 600; }
  .ok   { color: #15803d; font-weight: 600; }
  .no   { color: #b45309; font-weight: 600; }
  .err  { color: #b91c1c; }
  .btn  { display: inline-block; padding: .5rem .9rem; border-radius: 6px; text-decoration: none;
          background: #1a4f8a; color: #fff; margin-right: .5rem; }
  .btn.alt { background: #e5e7eb; color: #111; }
  .note { background: #fffbeb; border: 1px solid #fde68a; padding: .75rem; border-radius: 6px; }
</style>
</head>
<body>

<h1>solis-session-php</h1>

<table>
  <tr><th>Identity base (browser)</th><td><code><?= h($base) ?></code></td></tr>
  <tr><th>Identity base (server)</th><td><code><?= h($internal) ?></code><?= $internal !== $base ? ' <small>via fetcher</small>' : '' ?></td></tr>
  <tr><th>Mountpoint</th><td><code><?= $mount === '' ? '(empty)' : h($mount) ?></code>
      → library uses <code><?= $normalisedMount === '' ? '(none)' : h($normalisedMount) ?></code></td></tr>
  <tr><th>Workspace (tenant)</th><td><code><?= h($tenant) ?></code></td></tr>
  <tr><th>Application</th><td><?= $app === null ? '<em>none configured</em>' : '<code>' . h($app) . '</code>' ?></td></tr>
  <tr><th>solis_session cookie</th><td><?= isset($_COOKIE['solis_session']) ? '<span class="ok">present</span>' : '<span class="no">absent</span>' ?></td></tr>
</table>

<?php if ($error !== null): ?>
  <p class="err"><strong>Could not verify:</strong> <?= h($error) ?></p>
  <p class="note">Usually the JWKS fetch failed. Two things to check:
  solis-identity must be reachable at <code><?= h($internal) ?></code> from
  inside the container (on Docker Desktop the host is
  <code>host.docker.internal</code>, never <code>localhost</code>), and it must
  be <strong>listening on all interfaces</strong> —
  <code>rackup -p 4567</code> binds to 127.0.0.1 only, which no container can
  reach. Start it with <code>rackup -o 0.0.0.0 -p 4567</code>.</p>
<?php endif; ?>

<h2>Session</h2>
<?php if ($claims === null): ?>
  <p><span class="no">Not signed in.</span></p>
<?php else: ?>
  <p><span class="ok">Signed in</span> as <code><?= h($claims->email()) ?></code></p>
  <table>
    <tr><th>subject</th><td><code><?= h($claims->subject()) ?></code></td></tr>
    <tr><th>name</th><td><?= h($claims->name()) ?></td></tr>
    <tr><th>tenant</th><td><code><?= h($claims->tenant()) ?></code></td></tr>
    <tr><th>application</th><td><code><?= h($claims->application()) ?></code></td></tr>
    <tr><th>roles</th><td><code><?= h(implode(', ', $claims->roles())) ?></code></td></tr>
    <tr><th>super_admin?</th><td><?= $claims->isSuperAdmin() ? 'yes' : 'no' ?></td></tr>
    <?php if ($app !== null): ?>
      <tr><th>app_roles[<?= h($app) ?>]</th><td><code><?= h(implode(', ', $claims->appRoles($app))) ?></code></td></tr>
    <?php endif; ?>
    <tr><th>feePaid()</th><td><?= $claims->feePaid() ? 'true' : 'false' ?></td></tr>
  </table>
  <h3>All claims</h3>
  <pre><?= h(json_encode($claims->all(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
<?php endif; ?>

<h2>Where login would send you</h2>
<table>
  <tr>
    <th><code>loginUrl('<?= h($tenant) ?>')</code></th>
    <td><code><?= h($tenantLoginUrl) ?></code></td>
  </tr>
  <tr>
    <th><code>loginUrl()</code> — no argument</th>
    <td><code><?= h($session->loginUrl()) ?></code></td>
  </tr>
  <?php if ($appLoginUrl !== null): ?>
    <tr>
      <th>App-scoped (hand-built)</th>
      <td><code><?= h($appLoginUrl) ?></code></td>
    </tr>
  <?php endif; ?>
</table>

<p class="note">
  <code>loginUrl()</code> with no argument falls back to the <code>system</code>
  workspace — <code>service_name</code> is used for role lookups only and never
  appears in the URL. It also cannot build an app-scoped URL, which matters when
  the application pins its own login form or issues its own cookie: only the
  app-scoped route applies a <code>user_name</code> login identifier or sets a
  profile cookie. Both links below are live, so you can see the difference.
</p>

<p>
  <a class="btn" href="?login=1">Sign in (tenant-scoped)</a>
  <?php if ($appLoginUrl !== null): ?>
    <a class="btn" href="<?= h($appLoginUrl) ?>">Sign in (app-scoped)</a>
  <?php endif; ?>
  <a class="btn alt" href="<?= h($base . $mount . '/' . rawurlencode($tenant) . '/logout') ?>">Sign out</a>
</p>

</body>
</html>
