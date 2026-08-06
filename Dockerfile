# solis-session-php — test and demo container.
#
# Two targets:
#
#   test  (default) — installs the dev dependencies and runs PHPUnit.
#   demo            — serves a small page that exercises the library against a
#                     running solis-identity, with NO Composer install at all,
#                     which also proves the package's zero-runtime-dependency
#                     claim: src/ on disk plus ext-openssl is the whole story.
#
# Run the suite:
#   docker build -t solis-session-php . && docker run --rm solis-session-php
#
# Check another PHP version (the package supports >= 8.1):
#   docker build --build-arg PHP_VERSION=8.1 -t solis-session-php:8.1 .
#
# Interactive demo — see compose.yaml, or:
#   docker build --target demo -t solis-session-php:demo .
#   docker run --rm -p 8080:8080 \
#     -e SOLIS_IDENTITY_BASE=http://localhost:4567 \
#     -e SOLIS_IDENTITY_INTERNAL=http://host.docker.internal:4567 \
#     -e SOLIS_TENANT=acme -e SOLIS_APP=intranet \
#     solis-session-php:demo

ARG PHP_VERSION=8.2

# ── base ─────────────────────────────────────────────────────────────────
# ext-json is built into PHP 8 and ext-openssl is enabled in the official
# images, so there is nothing to compile — those are the only requirements.
FROM php:${PHP_VERSION}-cli-alpine AS base
WORKDIR /app
RUN php -r 'exit(extension_loaded("openssl") && extension_loaded("json") ? 0 : 1);' \
    || (echo "required extensions missing" && exit 1)

# ── demo ─────────────────────────────────────────────────────────────────
FROM base AS demo
COPY src/ ./src/
COPY examples/docker/ ./public/
ENV SOLIS_IDENTITY_BASE=http://localhost:4567 \
    SOLIS_MOUNTPOINT="" \
    SOLIS_TENANT=system \
    SOLIS_APP=""
EXPOSE 8080
CMD ["php", "-S", "0.0.0.0:8080", "-t", "public"]

# ── test ─────────────────────────────────────────────────────────────────
# Last on purpose: a plain `docker build` with no --target stops at the final
# stage, so the default image is the one that runs the suite.
FROM base AS test
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Manifest first so the install layer is reused while only source or tests
# change. No composer.lock: this is a library, so the lock file is not
# committed and the image resolves phpunit fresh — which is also what a
# consumer's own `composer install` will do.
COPY composer.json ./
RUN composer install --no-interaction --no-progress --no-scripts

COPY phpunit.xml ./
COPY src/ ./src/
COPY tests/ ./tests/

# Default command runs the suite; override to poke around, e.g.
#   docker run --rm -it solis-session-php sh
CMD ["vendor/bin/phpunit", "--colors=always"]
