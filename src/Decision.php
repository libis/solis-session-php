<?php

declare(strict_types=1);

namespace Solis\Session;

/**
 * A policy decision from the OPA sidecar.
 *
 * `allow` is the only guaranteed field — the composition root always defines it,
 * so a caller never has to test for its presence. Everything else is a
 * diagnostic or an obligation the caller may honour or ignore.
 *
 * The layer lists matter for support rather than for enforcement: a refusal
 * names the layer that produced it, so "why was I denied" is answerable even
 * when the denying layer belongs to a tenant the caller cannot see.
 *
 * Mirrors Solis::Session::PolicyClient::Decision in the Ruby gem. The two are
 * kept deliberately identical — a difference between them is a difference in
 * what a policy means depending on which language the service is written in.
 */
final class Decision
{
    /** @param array<string,mixed> $raw */
    public function __construct(private array $raw)
    {
    }

    /** @param array<string,mixed> $result the OPA `result` object */
    public static function from(array $result): self
    {
        return new self($result);
    }

    /** Every fail-closed refusal, so an outage is distinguishable from a policy denial. */
    public static function refused(string $reason): self
    {
        return new self([
            'allow'       => false,
            'reason'      => $reason,
            'deny_layers' => ['unavailable'],
        ]);
    }

    public function allow(): bool
    {
        return ($this->raw['allow'] ?? false) === true;
    }

    public function deny(): bool
    {
        return !$this->allow();
    }

    public function reason(): ?string
    {
        $reason = $this->raw['reason'] ?? null;
        return is_string($reason) ? $reason : null;
    }

    /** @return array<int,string> */
    public function denyLayers(): array
    {
        return $this->stringList('deny_layers');
    }

    /** @return array<int,string> */
    public function allowLayers(): array
    {
        return $this->stringList('allow_layers');
    }

    /**
     * Listing constraints. Never a plain array: the composition root sends an
     * object with completeness flags, and flattening it would turn its fields
     * into what reads like a list of clauses. A refusal, a fail-open decision
     * and an engine without filter support all yield unusable filters.
     */
    public function filters(): Filters
    {
        return Filters::from($this->raw['filters'] ?? null);
    }

    /** @return array<int,string> */
    public function allowedFields(): array
    {
        return $this->stringList('allowed_fields');
    }

    /** @return array<int,string> */
    public function deniedFields(): array
    {
        return $this->stringList('denied_fields');
    }

    /**
     * Resource fields the policy references that this request did not send.
     * A referenced-but-absent field makes its rule silently not fire, which for
     * a deny rule is fail-open — so this is the schema-drift signal, and it is
     * worth logging even on an allow.
     *
     * @return array<int,string>
     */
    public function absentFields(): array
    {
        return $this->stringList('absent_fields');
    }

    /** @return array<string,mixed> */
    public function all(): array
    {
        return $this->raw;
    }

    /** @return array<int,string> */
    private function stringList(string $key): array
    {
        $v = $this->raw[$key] ?? [];
        if (!is_array($v)) {
            return [];
        }
        return array_values(array_map('strval', $v));
    }
}
