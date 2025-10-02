<?php
declare(strict_types=1);

namespace App\Tests;

use App\Validator;
use InvalidArgumentException;

final class ValidatorTest extends TestCase
{
    public function testEnsureAuthPayloadValid(): void
    {
        $payload = [
            'avatar_uuid' => '123e4567-e89b-12d3-a456-426614174000',
            'password' => 'correcthorsebattery',
        ];

        Validator::ensureAuthPayload($payload);
        $this->addToAssertionCount(1);
    }

    public function testEnsureAuthPayloadInvalidUuid(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('invalid_uuid');
        Validator::ensureAuthPayload([
            'avatar_uuid' => 'bad',
            'password' => 'password123',
        ]);
    }
}
