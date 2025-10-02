<?php
declare(strict_types=1);

namespace App\Tests;

use App\Authorize;
use App\Db;
use App\Signer;

final class AuthorizeTest extends TestCase
{
    public function testAuthorizeReturnsSignedUrl(): void
    {
        $_SERVER['HTTP_X_CORRELATION_ID'] = 'corr';
        $_ENV['STORAGE_BASE_PATH'] = sys_get_temp_dir();
        $_ENV['DOWNLOAD_STRATEGY'] = 'signed_url';

        $assetPath = sys_get_temp_dir() . '/asset.bin';
        file_put_contents($assetPath, 'demo-data');

        $algo = \defined('PASSWORD_ARGON2ID') ? \PASSWORD_ARGON2ID : PASSWORD_DEFAULT;
        $this->pdo->prepare('INSERT INTO users (id, avatar_uuid, password_hash) VALUES (1, :uuid, :hash)')->execute([
            'uuid' => '123e4567-e89b-12d3-a456-426614174000',
            'hash' => password_hash('Password123!', $algo),
        ]);

        $this->pdo->prepare('INSERT INTO assets (id, type, location, content_type, filename) VALUES (:id, :type, :location, :content_type, :filename)')->execute([
            'id' => '123e4567-e89b-12d3-a456-426614174001',
            'type' => 'texture',
            'location' => $assetPath,
            'content_type' => 'application/octet-stream',
            'filename' => 'asset.bin',
        ]);

        $this->pdo->prepare('INSERT INTO permissions (user_id, asset_id, can_fetch) VALUES (1, :asset, 1)')->execute([
            'asset' => '123e4567-e89b-12d3-a456-426614174001',
        ]);

        $token = 'sampletoken';
        $this->pdo->prepare('INSERT INTO auth_tokens (token, user_id, expires_at) VALUES (:token, 1, :expires)')->execute([
            'token' => hash('sha256', $token),
            'expires' => (new \DateTimeImmutable('+10 minutes'))->format('Y-m-d H:i:s'),
        ]);

        $authorize = new Authorize(new Db($this->pdo), new Signer('test-secret'));
        $result = $authorize->authorize($token, 'asset', '123e4567-e89b-12d3-a456-426614174001');

        self::assertTrue($result['ok']);
        self::assertArrayHasKey('url', $result);
        self::assertStringContainsString('/api/download', $result['url']);
    }
}
