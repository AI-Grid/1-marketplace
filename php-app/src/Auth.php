<?php
declare(strict_types=1);

namespace App;

use DateInterval;
use DateTimeImmutable;
use PDO;

final class Auth
{
    private const DUMMY_HASH = '$argon2id$v=19$m=65536,t=4,p=1$w6uJ9wH14r2raXIiQun7pA$qls9B0xOSq2zu60zJtWWUw';

    private Db $db;
    private int $tokenTtl;
    private int|string $passwordAlgo;

    public function __construct(?Db $db = null)
    {
        $this->db = $db ?? new Db();
        $this->tokenTtl = max(60, (int)($_ENV['TOKEN_TTL_SECONDS'] ?? '600'));
        $this->passwordAlgo = \defined('PASSWORD_ARGON2ID') ? \PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
    }

    public function authenticate(string $avatarUuid, string $password): array
    {
        Validator::assertPassword($password);
        if (!Validator::isUuid($avatarUuid)) {
            return $this->error('invalid_uuid', 'Invalid avatar identifier');
        }

        $pdo = $this->db->pdo();
        $stmt = $pdo->prepare('SELECT id, password_hash FROM users WHERE avatar_uuid = :uuid LIMIT 1');
        $stmt->execute(['uuid' => $avatarUuid]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        $hash = $row['password_hash'] ?? self::DUMMY_HASH;
        $valid = password_verify($password, $hash);
        if ($valid && isset($row['id'])) {
            if (password_needs_rehash($hash, $this->passwordAlgo)) {
                $newHash = password_hash($password, $this->passwordAlgo);
                $update = $pdo->prepare('UPDATE users SET password_hash = :hash WHERE id = :id');
                $update->execute(['hash' => $newHash, 'id' => $row['id']]);
            }

            [$token, $expiresAt] = $this->issueToken((int)$row['id']);
            return [
                'ok' => true,
                'token' => $token,
                'expires_at' => $expiresAt->format(DATE_ATOM),
                'correlation_id' => $_SERVER['HTTP_X_CORRELATION_ID'] ?? null,
            ];
        }

        // Delay to mitigate brute force attempts.
        usleep(50000);
        return $this->error('auth_failed', 'Authentication failed');
    }

    private function issueToken(int $userId): array
    {
        $token = bin2hex(random_bytes(32));
        $expires = (new DateTimeImmutable('now'))->add(new DateInterval('PT' . $this->tokenTtl . 'S'));

        $stmt = $this->db->pdo()->prepare('INSERT INTO auth_tokens (token, user_id, expires_at, created_at) VALUES (:token, :user_id, :expires_at, CURRENT_TIMESTAMP)');
        $stmt->execute([
            'token' => hash('sha256', $token),
            'user_id' => $userId,
            'expires_at' => $expires->format('Y-m-d H:i:s'),
        ]);

        return [$token, $expires];
    }

    private function error(string $code, string $message): array
    {
        return [
            'ok' => false,
            'error_code' => $code,
            'message' => $message,
            'correlation_id' => $_SERVER['HTTP_X_CORRELATION_ID'] ?? null,
        ];
    }
}
