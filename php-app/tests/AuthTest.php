<?php
declare(strict_types=1);

namespace App\Tests;

use App\Auth;
use App\Db;

final class AuthTest extends TestCase
{
    public function testAuthenticateIssuesToken(): void
    {
        $_SERVER['HTTP_X_CORRELATION_ID'] = 'test-correlation';
        $algo = \defined('PASSWORD_ARGON2ID') ? \PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        $hash = password_hash('Password123!', $algo);
        $stmt = $this->pdo->prepare('INSERT INTO users (avatar_uuid, password_hash) VALUES (:uuid, :hash)');
        $stmt->execute([
            'uuid' => '123e4567-e89b-12d3-a456-426614174000',
            'hash' => $hash,
        ]);

        $auth = new Auth(new Db($this->pdo));
        $result = $auth->authenticate('123e4567-e89b-12d3-a456-426614174000', 'Password123!');

        self::assertTrue($result['ok']);
        self::assertArrayHasKey('token', $result);
        self::assertSame('test-correlation', $result['correlation_id']);

        $count = (int)$this->pdo->query('SELECT COUNT(*) FROM auth_tokens')->fetchColumn();
        self::assertSame(1, $count);
    }
}
