<?php

declare(strict_types=1);

namespace Solis\Session;

/**
 * Reads and writes user attributes on solis-identity
 * (/api/users/:email/attributes).
 *
 * Attributes are the counterpart to the KV claim store, and the difference is
 * what reaches a token. A KV value is projected into the JWT at issuance and is
 * therefore write-only from here — you read it back off Solis\Session\Claims.
 * An attribute never enters a token at all, so this client both reads and
 * writes: an app looks up what it needs at request time, and the value can
 * change without anyone reissuing a session.
 *
 * Use attributes for what an app wants to *know* about a person (preferences,
 * profile extras, an external record id); use KV for what the platform needs to
 * *decide* with (entitlements that gate access).
 *
 * Auth is a scoped SOLIS API key, like KvClient — attributes:read for readers,
 * attributes:write for writers, or attributes:* for both. The key's own account
 * also bounds reach: unless it belongs to a super_admin, it only sees users in
 * its owner's workspace.
 *
 *   $attrs = new Solis\Session\AttributesClient(
 *       'https://identity.example.com',
 *       getenv('SOLIS_ATTRS_API_KEY'),
 *       ['mountpoint' => '_']
 *   );
 *
 *   $attrs->all('jane@example.com');                  // ['orcid' => '0000-…']
 *   $attrs->get('jane@example.com', 'orcid');         // '0000-…' (null if absent)
 *   $attrs->set('jane@example.com', 'seats', 5);
 *   $attrs->merge('jane@example.com', ['a' => 1, 'b' => null]);  // null deletes 'b'
 *   $attrs->replace('jane@example.com', ['only' => 'this']);
 *   $attrs->delete('jane@example.com', 'seats');
 *
 * In a request the email comes off the validated session, so the common call is
 * $attrs->forClaims($claims).
 */
final class AttributesClient
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
        $this->baseUrl = rtrim($identityBase, '/') . ($mp === '' ? '' : '/' . $mp);
        $this->apiKey  = $apiKey;
        $this->timeout = (int) ($options['timeout'] ?? 5);
        $this->transport = $options['transport'] ?? null;
    }

    /**
     * Every attribute for a user.
     *
     * @return array<string,mixed>
     */
    public function all(string $email): array
    {
        $res = $this->request('GET', $this->pathFor($email), null);
        return is_array($res['attributes'] ?? null) ? $res['attributes'] : [];
    }

    /**
     * One attribute, or null when it is not set.
     *
     * The server answers 404 for an absent key rather than a null value, so
     * "not set" and "set to null" stay distinguishable; this collapses both to
     * null because that is what a caller reaching for one value wants. Use
     * all() and array_key_exists() when the difference matters.
     */
    public function get(string $email, string $key): mixed
    {
        try {
            $res = $this->request('GET', $this->pathFor($email) . '/' . rawurlencode($key), null);
        } catch (Exception $e) {
            if ($e->getCode() === 404) {
                return null;
            }
            throw $e;
        }
        return $res['value'] ?? null;
    }

    /** Set one attribute. Returns the stored value. */
    public function set(string $email, string $key, mixed $value): mixed
    {
        $res = $this->request(
            'PUT',
            $this->pathFor($email) . '/' . rawurlencode($key),
            json_encode(['value' => $value])
        );
        return $res['value'] ?? null;
    }

    /**
     * Merge into what is stored. A null value removes that key — JSON has no
     * other way to say "delete this".
     *
     * @param array<string,mixed> $attributes
     * @return array<string,mixed>
     */
    public function merge(string $email, array $attributes): array
    {
        $res = $this->request('PATCH', $this->pathFor($email), json_encode(['attributes' => $attributes]));
        return is_array($res['attributes'] ?? null) ? $res['attributes'] : [];
    }

    /**
     * Replace the whole hash.
     *
     * @param array<string,mixed> $attributes
     * @return array<string,mixed>
     */
    public function replace(string $email, array $attributes): array
    {
        $res = $this->request('PUT', $this->pathFor($email), json_encode(['attributes' => $attributes]));
        return is_array($res['attributes'] ?? null) ? $res['attributes'] : [];
    }

    /** Remove one attribute. Returns true when it was there to remove. */
    public function delete(string $email, string $key): bool
    {
        $res = $this->request('DELETE', $this->pathFor($email) . '/' . rawurlencode($key), null);
        return ($res['deleted'] ?? false) === true;
    }

    /**
     * Remove all of them.
     *
     * @return array<string,mixed>
     */
    public function clear(string $email): array
    {
        $res = $this->request('DELETE', $this->pathFor($email), null);
        return is_array($res['attributes'] ?? null) ? $res['attributes'] : [];
    }

    /**
     * Convenience for the in-request case: attributes of the user the validated
     * session belongs to. Returns [] when there is no session, so a guest-mode
     * service can call it unconditionally.
     *
     * @return array<string,mixed>
     */
    public function forClaims(?Claims $claims): array
    {
        $email = $claims?->email();
        if ($email === null || trim($email) === '') {
            return [];
        }
        return $this->all($email);
    }

    private function pathFor(string $email): string
    {
        return $this->baseUrl . '/api/users/' . rawurlencode($email) . '/attributes';
    }

    /**
     * @return array<string,mixed>
     */
    private function request(string $method, string $url, ?string $body): array
    {
        $headers = ['Authorization: ApiKey ' . $this->apiKey];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
        }

        [$status, $respBody] = $this->send($method, $url, $headers, $body);
        if ($status !== 200) {
            // The status rides along as the exception code so get() can branch
            // on 404 without parsing the message.
            throw new Exception("Attributes $method failed ($status): $respBody", $status);
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
            throw new Exception("Attributes request failed: $err");
        }
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return [$status, (string) $resp];
    }
}
