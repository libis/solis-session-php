<?php

declare(strict_types=1);

namespace Solis\Session;

/**
 * Manages user accounts on solis-identity (/api/users).
 *
 * The lifecycle of the account itself — create, rename, suspend, remove — as
 * opposed to AttributesClient, which reads and writes free-form data *inside*
 * an account that already exists. The two are easy to confuse: this client
 * cannot touch attributes, and AttributesClient cannot create or delete a user.
 *
 * Auth is a raw SOLIS API key (Authorization: ApiKey <raw>), but unlike KV and
 * attributes the key's *scopes* are not what decides here — the key's owning
 * account must hold super_admin or tenant_admin. A tenant_admin key only
 * reaches users with a membership in its own tenant, and can never grant
 * super_admin. Delete additionally requires super_admin.
 *
 *   $users = new Solis\Session\UsersClient(
 *       'https://identity.example.com',
 *       getenv('SOLIS_USERS_API_KEY')
 *   );
 *
 *   $users->create('jane@example.com', 'Jane Doe');   // invited + welcome mail
 *   $users->find('jane@example.com');
 *   $users->update('jane@example.com', ['name' => 'Jane R. Doe']);
 *   $users->disable('jane@example.com');
 *   $users->enable('jane@example.com');
 *   $users->invite('jane@example.com');               // re-send set-password mail
 *   $users->renew('jane@example.com');                // re-date from its account profile
 *   $users->changeEmail('jane@example.com', 'jane.doe@example.com');
 *   $users->delete('jane@example.com');               // to trash, restorable
 *
 * Password *recovery* is deliberately absent: the reset flow is rate limited,
 * enumeration-safe and token-bound on the identity server, so an application
 * sends people to <identityBase>/<tenant>/auth/reset rather than driving it
 * over the API. resetUrl() builds that link. invite() is the administrator-side
 * counterpart, for a welcome link that expired or never arrived.
 */
final class UsersClient
{
    private string $baseUrl;
    private string $apiKey;
    private int $timeout;

    /** @var callable(string,string,array,?string):array{0:int,1:string}|null */
    private $transport;

    /**
     * @param array{mountpoint?:string, timeout?:int, transport?:callable} $options
     *   transport is a test seam: fn(method, url, headers[], body): [status, body]
     */
    public function __construct(string $identityBase, string $apiKey, array $options = [])
    {
        if (trim($identityBase) === '') {
            throw new Exception('identityBase is required');
        }
        if (trim($apiKey) === '') {
            throw new Exception('apiKey is required');
        }
        $mp = trim($options['mountpoint'] ?? '', '/');
        $this->baseUrl   = rtrim($identityBase, '/') . ($mp === '' ? '' : '/' . $mp);
        $this->apiKey    = $apiKey;
        $this->timeout   = (int) ($options['timeout'] ?? 5);
        $this->transport = $options['transport'] ?? null;
    }

    /**
     * One user, or null when there is no such account.
     *
     * 404 collapses to null because "does this account exist?" is the question
     * a caller reaching for one user is usually asking. Every other non-200
     * still throws.
     *
     * @return array<string,mixed>|null
     */
    public function find(string $email): ?array
    {
        try {
            return $this->request('GET', $this->pathFor($email), null);
        } catch (Exception $e) {
            if ($e->getCode() === 404) {
                return null;
            }
            throw $e;
        }
    }

    /**
     * Provision an account.
     *
     * With no 'password' in $fields the account is created `invited` and
     * identity mails a set-password link — the calling application never
     * handles a password, which is the reason to prefer it. Passing one creates
     * an already-active account instead.
     *
     * The name doubles as a login handle for applications configured that way,
     * so it must be unique platform-wide; a clash throws with code 409.
     *
     * $fields may carry 'account_profile' to put the account on a named
     * lifecycle policy from the start. Without one, identity applies the
     * application's or the workspace's default, which is usually what you
     * want — pass it only to override that.
     *
     *   $users->create('jane@example.com', 'Jane Doe', ['account_profile' => 'guest']);
     *
     * @param array{password?:string, roles?:array<int,string>, app_roles?:array<string,array<int,string>>, tenant?:string, api_keys_enabled?:bool, account_profile?:?string, expires_at?:?string} $fields
     * @return array<string,mixed>
     */
    public function create(string $email, string $name, array $fields = []): array
    {
        return $this->request(
            'POST',
            $this->baseUrl . '/api/users',
            json_encode(array_merge($fields, ['email' => $email, 'name' => $name])),
            201
        );
    }

    /**
     * Partial update — a $fields naming only 'name' changes only the name.
     *
     * Accepts name, roles, app_roles, api_keys_enabled, password,
     * account_profile and expires_at. Roles and app_roles apply to one
     * membership: the key's own tenant for a tenant_admin, or 'tenant'
     * (defaulting to the user's primary) for a super_admin; other memberships
     * are left alone.
     *
     * The two lifecycle fields follow the same rule as the admin form: the
     * profile decides the policy and materialises a date, while an explicit
     * expires_at overrides it for this account only. A body naming both takes
     * the date. Either set to null clears the expiry. An unknown profile slug
     * throws with code 422 rather than silently clearing it.
     *
     *   $users->update('jane@example.com', ['account_profile' => 'guest']);
     *   $users->update('jane@example.com', ['expires_at' => '2030-06-15']);
     *   $users->update('jane@example.com', ['account_profile' => null]);
     *
     * The address and the status are not updatable here — changeEmail() also
     * notifies the old address, and enable()/disable() guard against locking
     * yourself out. Sending them throws with code 422 rather than being
     * silently ignored.
     *
     * @param array<string,mixed> $fields
     * @return array<string,mixed>
     */
    public function update(string $email, array $fields): array
    {
        return $this->request('PATCH', $this->pathFor($email), json_encode($fields));
    }

    /** Clear any blocked status. */
    public function enable(string $email): array
    {
        return $this->request('POST', $this->pathFor($email) . '/enable', null);
    }

    /**
     * Suspend without deleting. The record, memberships, password and API keys
     * all survive, so enable() is a pure status flip. A disabled account cannot
     * sign in, cannot use its API keys, and is not sent password-reset mail.
     */
    public function disable(string $email): array
    {
        return $this->request('POST', $this->pathFor($email) . '/disable', null);
    }

    /**
     * Rename the account. Immediate — no confirmation round-trip, because the
     * API key is already the proof the self-service flow at /profile has to
     * establish. The old address is notified.
     */
    public function changeEmail(string $email, string $newEmail): array
    {
        return $this->request(
            'POST',
            $this->pathFor($email) . '/change-email',
            json_encode(['new_email' => $newEmail])
        );
    }

    /**
     * (Re)send the set-password mail — the fix for a welcome link that expired
     * or never arrived. Local accounts only (422 for SSO-backed ones); throws
     * with code 503 when no mail server is configured.
     */
    public function invite(string $email): array
    {
        return $this->request('POST', $this->pathFor($email) . '/invite', null);
    }

    /**
     * Re-date an account from its own account profile, counting from now
     * rather than from a creation date already in the past, and clear an
     * 'expired' status.
     *
     * This is the counterpart to an account that has lapsed rather than been
     * suspended — the two are separate facts, and enable() deliberately does
     * NOT extend an expiry, so lifting a suspension cannot silently undo a
     * lapse. Check 'expired' on the record to tell which applies:
     *
     *   $user = $users->find('jane@example.com');
     *   if ($user['expired']) { $users->renew('jane@example.com'); }
     *
     * Throws with code 422 ('no_account_profile') when the account carries no
     * profile to renew from. An account given an explicit expiry date is
     * extended with update() instead, which is also how you move one onto a
     * different profile.
     *
     * @return array<string,mixed>
     */
    public function renew(string $email): array
    {
        return $this->request('POST', $this->pathFor($email) . '/renew', null);
    }

    /**
     * Move the account to trash. Restorable from the admin UI, not an erase.
     *
     * Requires a super_admin key: a tenant_admin key gets 403 here by design,
     * while every other call in this client works for it.
     */
    public function delete(string $email): bool
    {
        $res = $this->request('DELETE', $this->pathFor($email), null);
        return ($res['deleted'] ?? false) === true;
    }

    /**
     * Where to send someone who forgot their password.
     *
     * Recovery stays on the identity server on purpose — it owns the token
     * lifetime, the single-use guarantee, the per-address and per-IP rate
     * limits, and the neutral "if that address exists we sent a mail" response
     * that keeps the form from confirming who holds an account. Point a
     * "Forgot your password?" link here; there is no return_to on this flow, so
     * the user comes back through the normal login route afterwards.
     *
     * Note the tenant slug: the tenant-scoped URL applies that tenant's
     * branding to the page and the mail.
     */
    public function resetUrl(string $tenant): string
    {
        return $this->baseUrl . '/' . rawurlencode($tenant) . '/auth/reset';
    }

    private function pathFor(string $email): string
    {
        return $this->baseUrl . '/api/users/' . rawurlencode($email);
    }

    /**
     * @return array<string,mixed>
     */
    private function request(string $method, string $url, ?string $body, int $expect = 200): array
    {
        $headers = ['Authorization: ApiKey ' . $this->apiKey];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
        }

        [$status, $respBody] = $this->send($method, $url, $headers, $body);
        if ($status !== $expect) {
            // The status rides along as the exception code so a caller can
            // branch on 404/409/422 without parsing the message.
            throw new Exception("Users $method failed ($status): $respBody", $status);
        }
        $decoded = json_decode($respBody, true);
        return is_array($decoded) ? $decoded : [];
    }

    /**
     * Single HTTP seam — tests inject `transport` to avoid a real request.
     *
     * @param array<int,string> $headers
     * @return array{0:int,1:string}
     */
    private function send(string $method, string $url, array $headers, ?string $body): array
    {
        if ($this->transport !== null) {
            return ($this->transport)($method, $url, $headers, $body);
        }
        $ch = curl_init($url);
        $opts = [
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => $this->timeout,
        ];
        if ($body !== null) {
            $opts[CURLOPT_POSTFIELDS] = $body;
        }
        curl_setopt_array($ch, $opts);
        $resp = curl_exec($ch);
        if ($resp === false) {
            $err = curl_error($ch);
            curl_close($ch);
            throw new Exception("Users request failed: $err");
        }
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return [$status, (string) $resp];
    }
}
