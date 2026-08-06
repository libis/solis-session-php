<?php

declare(strict_types=1);

namespace Solis\Session;

/**
 * Raised for any token/JWKS validation failure. Callers that want to treat all
 * auth failures uniformly (redirect / 401) can catch this single type.
 */
class Exception extends \RuntimeException
{
}
