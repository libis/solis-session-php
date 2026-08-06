<?php

declare(strict_types=1);

namespace Solis\Session;

/**
 * Writes to solis-identity's KV claim store (PUT/DELETE /kv/:namespace/:key).
 *
 * The KV store is a projection that feeds JWT claims via the identity server's
 * :kv resolver, so this client only WRITES. Reading happens server-side at
 * token issuance; a consuming app reads the resulting claim from its validated
 * token (Solis\Session\Claims), never from here.
 *
 * Auth is a scoped SOLIS API key (scope kv:<namespace> or kv:*), NOT the
 * session cookie — a KV push is a privileged operation at a different trust
 * level than a user session.
 *
 *   $kv = new Solis\Session\KvClient('https://identity.example.com', getenv('SOLIS_KV_API_KEY'));
 *   $kv->set('fee_paid', 'acme', true);     // ['ok' => true, ...]
 *   $kv->delete('fee_paid', 'acme');        // ['ok' => true, 'deleted' => true]
 */
final class KvClient
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
     * Upsert a value. Returns the decoded JSON response. Throws on any non-200
     * (401 bad key, 403 wrong scope, 400 bad value/component).
     *
     * @return array<string,mixed>
     */
    public function set(string $namespace, string $key, mixed $value): array
    {
        return $this->request('PUT', $namespace, $key, json_encode(['value' => $value]));
    }

    /**
     * Delete a key. Returns the decoded response (['ok' => true, 'deleted' => …]).
     *
     * @return array<string,mixed>
     */
    public function delete(string $namespace, string $key): array
    {
        return $this->request('DELETE', $namespace, $key, null);
    }

    /**
     * @return array<string,mixed>
     */
    private function request(string $method, string $namespace, string $key, ?string $body): array
    {
        $url = $this->baseUrl . '/kv/' . rawurlencode($namespace) . '/' . rawurlencode($key);
        $headers = ['Authorization: ApiKey ' . $this->apiKey];
        if ($body !== null) {
            $headers[] = 'Content-Type: application/json';
        }

        [$status, $respBody] = $this->send($method, $url, $headers, $body);
        if ($status !== 200) {
            throw new Exception("KV $method failed ($status): $respBody");
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
            throw new Exception("KV request failed: $err");
        }
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return [$status, (string) $resp];
    }
}
