<?php

declare(strict_types=1);

namespace Solis\Session;

/**
 * Typed, read-only view over a verified JWT payload. Mirrors the claim shape
 * solis-identity's ProfileEngine emits (tenant, roles, app_roles, plus any
 * resolver-injected claims such as fee_paid).
 */
final class Claims
{
    /** @param array<string,mixed> $claims */
    public function __construct(private array $claims)
    {
    }

    public function subject(): string
    {
        return (string) ($this->claims['sub'] ?? '');
    }

    public function email(): string
    {
        return (string) ($this->claims['email'] ?? '');
    }

    public function name(): string
    {
        return (string) ($this->claims['preferred_username'] ?? $this->claims['name'] ?? '');
    }

    public function tenant(): string
    {
        return (string) ($this->claims['tenant'] ?? '');
    }

    public function application(): string
    {
        return (string) ($this->claims['application'] ?? '');
    }

    /** @return string[] */
    public function roles(): array
    {
        return array_map('strval', (array) ($this->claims['roles'] ?? []));
    }

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->roles(), true);
    }

    public function isSuperAdmin(): bool
    {
        return $this->hasRole('super_admin');
    }

    /**
     * Roles the user holds within a given application (app_roles[$app]).
     *
     * @return string[]
     */
    public function appRoles(string $app): array
    {
        $map = (array) ($this->claims['app_roles'] ?? []);
        return array_map('strval', (array) ($map[$app] ?? []));
    }

    public function hasAppRole(string $app, string $role): bool
    {
        return in_array($role, $this->appRoles($app), true);
    }

    /** @return string[] */
    public function groups(): array
    {
        return array_map('strval', (array) ($this->claims['groups'] ?? []));
    }

    /**
     * Membership / fee status projected by the registry via the :kv resolver.
     * Absent claim (registry silent / unpaid) → false.
     */
    public function feePaid(): bool
    {
        return ($this->claims['fee_paid'] ?? false) === true;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->claims[$key] ?? $default;
    }

    /** @return array<string,mixed> */
    public function all(): array
    {
        return $this->claims;
    }
}
