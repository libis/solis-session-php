<?php

declare(strict_types=1);

// Prefer Composer's autoloader when dependencies are installed; otherwise fall
// back to a minimal PSR-4 autoloader so the src/ classes load standalone. The
// package itself has no runtime Composer dependencies (ext-openssl only), so
// this keeps it testable and usable before `composer install`.
$composer = __DIR__ . '/../vendor/autoload.php';
if (is_file($composer)) {
    require $composer;
    return;
}

spl_autoload_register(static function (string $class): void {
    $prefix = 'Solis\\Session\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    // Tests\Foo → tests/Foo.php ; Foo → src/Foo.php
    if (str_starts_with($relative, 'Tests\\')) {
        $path = __DIR__ . '/' . str_replace('\\', '/', substr($relative, strlen('Tests\\'))) . '.php';
    } else {
        $path = __DIR__ . '/../src/' . str_replace('\\', '/', $relative) . '.php';
    }
    if (is_file($path)) {
        require $path;
    }
});
