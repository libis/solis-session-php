<?php

declare(strict_types=1);

namespace Solis\Session;

/**
 * What a caller may see across a whole collection, as constraints on a row
 * rather than an answer about one.
 *
 * A listing cannot ask "may I read assets" — there is no such question — so it
 * asks with no resource and reads this instead. Each clause is a conjunction of
 * terms; the clauses are a disjunction:
 *
 *   visible = OR(allow clauses) AND NOT OR(deny clauses)
 *
 * The two completeness flags are not decoration, and they are not symmetric.
 * `allow_complete` false means a rule could not be expressed as a filter, so the
 * list may be SHORT — show it, and say so. `deny_complete` false means a
 * restriction could not be expressed, so the list would be LONG: it would contain
 * rows the policy refuses. That is not a degraded listing, it is a disclosure, and
 * isUsable() is false.
 *
 * Absent or malformed filters are treated as unusable rather than as
 * unrestricted, so a policy engine that does not supply them cannot be mistaken
 * for one that permits everything.
 *
 * Mirrors Solis::Session::PolicyClient::Filters in the Ruby gem. Two places differ,
 * both only on input the composition root never sends, and both towards refusing:
 *
 *  - An empty JSON object `{}` decodes to the same PHP value as `[]`, so it cannot
 *    be told apart from the old bare-array shape. It is unusable here; Ruby reads
 *    `{}` as usable with no clauses.
 *  - `allow` or `deny` present but not a list marks that side incomplete, where
 *    Ruby would coerce it with Array().
 */
final class Filters
{
    /**
     * @param array<int,mixed> $allow
     * @param array<int,mixed> $deny
     */
    public function __construct(
        private array $allow = [],
        private array $deny = [],
        private bool $allowComplete = true,
        private bool $denyComplete = true
    ) {
    }

    /** No usable filters: what a refusal, a transport failure, or an engine without filter support produce. */
    public static function none(): self
    {
        return new self([], [], false, false);
    }

    /**
     * @param mixed $raw the decision's `filters` value, as decoded by json_decode(…, true)
     */
    public static function from(mixed $raw): self
    {
        // Must be a JSON object. A list is the old bare-array shape, which carries no
        // completeness flags and so is malformed rather than "clauses with nothing
        // restricting them" — the Array()-on-a-Hash trap in the other direction.
        if (!is_array($raw) || $raw === [] || array_is_list($raw)) {
            return self::none();
        }

        [$allow, $allowOk] = self::clauses($raw, 'allow');
        [$deny, $denyOk]   = self::clauses($raw, 'deny');

        return new self(
            $allow,
            $deny,
            $allowOk && ($raw['allow_complete'] ?? true) !== false,
            $denyOk && ($raw['deny_complete'] ?? true) !== false
        );
    }

    /**
     * @param array<string,mixed> $raw
     * @return array{0:array<int,mixed>,1:bool} the clauses, and whether they were well-formed
     */
    private static function clauses(array $raw, string $key): array
    {
        if (!array_key_exists($key, $raw) || $raw[$key] === null) {
            return [[], true];
        }
        $v = $raw[$key];
        return is_array($v) && array_is_list($v) ? [$v, true] : [[], false];
    }

    /** @return array<int,mixed> */
    public function allow(): array
    {
        return $this->allow;
    }

    /** @return array<int,mixed> */
    public function deny(): array
    {
        return $this->deny;
    }

    /**
     * Whether a listing may be built from these at all. Only the deny side decides:
     * an incomplete allow costs rows, an incomplete deny costs the boundary.
     */
    public function isUsable(): bool
    {
        return $this->denyComplete;
    }

    /** True when every allow rule was expressible, so the listing is the whole answer rather than a safe subset. */
    public function isComplete(): bool
    {
        return $this->allowComplete;
    }

    /**
     * No clause allows anything, so the caller sees nothing. Distinct from unusable:
     * this is a real answer, and an empty listing is correct.
     */
    public function isNone(): bool
    {
        return $this->allow === [];
    }

    /** @return array{allow:array<int,mixed>,deny:array<int,mixed>,allow_complete:bool,deny_complete:bool} */
    public function toArray(): array
    {
        return [
            'allow'          => $this->allow,
            'deny'           => $this->deny,
            'allow_complete' => $this->allowComplete,
            'deny_complete'  => $this->denyComplete,
        ];
    }
}
