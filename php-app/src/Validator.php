<?php
declare(strict_types=1);

namespace App;

use InvalidArgumentException;

final class Validator
{
    private const UUID_REGEX = '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/';
    private const REQUEST_TYPES = ['asset', 'inventory', 'package'];

    public static function ensureAuthPayload(array $payload): void
    {
        if (!isset($payload['avatar_uuid'], $payload['password'])) {
            throw new InvalidArgumentException('invalid_payload');
        }

        if (!self::isUuid((string)$payload['avatar_uuid'])) {
            throw new InvalidArgumentException('invalid_uuid');
        }

        self::assertPassword((string)$payload['password']);
    }

    public static function ensureAuthorizePayload(array $payload): void
    {
        if (!isset($payload['token'], $payload['request'], $payload['id'])) {
            throw new InvalidArgumentException('invalid_payload');
        }

        if (!is_string($payload['token']) || $payload['token'] === '') {
            throw new InvalidArgumentException('auth_failed');
        }

        self::assertRequest((string)$payload['request']);

        if (!self::isUuid((string)$payload['id'])) {
            throw new InvalidArgumentException('invalid_id');
        }
    }

    public static function isUuid(string $value): bool
    {
        return (bool)preg_match(self::UUID_REGEX, $value);
    }

    public static function assertPassword(string $password): void
    {
        if (strlen($password) < 8) {
            throw new InvalidArgumentException('invalid_password');
        }
    }

    public static function assertRequest(string $request): void
    {
        if (!in_array($request, self::REQUEST_TYPES, true)) {
            throw new InvalidArgumentException('invalid_request');
        }
    }
}
