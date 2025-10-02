<?php
declare(strict_types=1);

namespace App;

use DateInterval;
use DateTimeImmutable;
use PDO;
use RuntimeException;

final class Authorize
{
    private Db $db;
    private Signer $signer;
    private int $signedUrlTtl;
    private string $strategy;
    private string $storageBasePath;

    public function __construct(?Db $db = null, ?Signer $signer = null)
    {
        $this->db = $db ?? new Db();
        $secret = $_ENV['HMAC_SECRET'] ?? '';
        $this->signer = $signer ?? new Signer($secret);
        $this->signedUrlTtl = max(300, (int)($_ENV['SIGNED_URL_TTL_SECONDS'] ?? '600'));
        $this->strategy = strtolower($_ENV['DOWNLOAD_STRATEGY'] ?? 'signed_url');
        $this->storageBasePath = rtrim($_ENV['STORAGE_BASE_PATH'] ?? '', '/');
    }

    public function authorize(string $token, string $request, string $id): array
    {
        if (!Validator::isUuid($id)) {
            return $this->error('invalid_id', 'Invalid identifier supplied');
        }

        Validator::assertRequest($request);

        $tokenRecord = $this->lookupToken($token);
        if ($tokenRecord === null) {
            return $this->error('auth_failed', 'Authentication token is invalid or expired');
        }

        return match ($request) {
            'asset', 'package' => $this->authorizeAsset((int)$tokenRecord['user_id'], $id),
            'inventory' => $this->authorizeInventory((int)$tokenRecord['user_id']),
            default => $this->error('invalid_request', 'Unsupported request type'),
        };
    }

    public function downloadAsset(string $id): array
    {
        $pdo = $this->db->pdo();
        $stmt = $pdo->prepare('SELECT id, type, location, content_type, filename FROM assets WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $id]);
        $asset = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$asset) {
            return $this->error('not_found', 'Asset not found');
        }

        $path = $this->resolveLocation($asset['location']);
        if (!is_readable($path)) {
            return $this->error('not_found', 'Asset content missing');
        }

        $contentType = $asset['content_type'] ?: (mime_content_type($path) ?: 'application/octet-stream');
        return [
            'ok' => true,
            'path' => $path,
            'content_type' => $contentType,
            'filename' => $asset['filename'] ?? basename($path),
        ];
    }

    private function authorizeAsset(int $userId, string $assetId): array
    {
        $pdo = $this->db->pdo();
        $stmt = $pdo->prepare('SELECT a.id, a.type, a.location, a.content_type, a.filename FROM assets a INNER JOIN permissions p ON p.asset_id = a.id WHERE p.user_id = :user AND a.id = :asset LIMIT 1');
        $stmt->execute(['user' => $userId, 'asset' => $assetId]);
        $asset = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$asset) {
            return $this->error('not_authorized', 'Access denied or asset not found');
        }

        $metadata = [
            'id' => $asset['id'],
            'type' => $asset['type'],
            'filename' => $asset['filename'],
        ];

        if ($this->strategy === 'inline') {
            $path = $this->resolveLocation($asset['location']);
            if (!is_readable($path)) {
                return $this->error('not_found', 'Asset not found on storage');
            }

            $binary = base64_encode((string)file_get_contents($path));
            return [
                'ok' => true,
                'content_type' => $asset['content_type'] ?: (mime_content_type($path) ?: 'application/octet-stream'),
                'binary' => $binary,
                'metadata' => $metadata,
                'correlation_id' => $_SERVER['HTTP_X_CORRELATION_ID'] ?? null,
            ];
        }

        $expires = (new DateTimeImmutable('now'))->add(new DateInterval('PT' . $this->signedUrlTtl . 'S'));
        $signature = $this->signer->sign($asset['id'], $expires->getTimestamp());
        $baseUrl = rtrim($_ENV['APP_BASE_URL'] ?? inferBaseUrl(), '/');
        $url = sprintf('%s/api/download?id=%s&expires=%d&sig=%s', $baseUrl, rawurlencode($asset['id']), $expires->getTimestamp(), $signature);

        return [
            'ok' => true,
            'url' => $url,
            'metadata' => $metadata,
            'correlation_id' => $_SERVER['HTTP_X_CORRELATION_ID'] ?? null,
        ];
    }

    private function authorizeInventory(int $userId): array
    {
        $pdo = $this->db->pdo();
        $stmt = $pdo->prepare('SELECT a.id, a.type, a.filename FROM assets a INNER JOIN permissions p ON p.asset_id = a.id WHERE p.user_id = :user ORDER BY a.filename');
        $stmt->execute(['user' => $userId]);
        $assets = $stmt->fetchAll(PDO::FETCH_ASSOC);

        return [
            'ok' => true,
            'metadata' => [
                'assets' => $assets,
                'count' => count($assets),
            ],
            'correlation_id' => $_SERVER['HTTP_X_CORRELATION_ID'] ?? null,
        ];
    }

    private function lookupToken(string $token): ?array
    {
        $hashed = hash('sha256', $token);
        $stmt = $this->db->pdo()->prepare('SELECT user_id, expires_at FROM auth_tokens WHERE token = :token LIMIT 1');
        $stmt->execute(['token' => $hashed]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            return null;
        }

        $expires = new DateTimeImmutable($row['expires_at']);
        if ($expires < new DateTimeImmutable('now')) {
            $delete = $this->db->pdo()->prepare('DELETE FROM auth_tokens WHERE token = :token');
            $delete->execute(['token' => $hashed]);
            return null;
        }

        return $row;
    }

    private function resolveLocation(string $location): string
    {
        $path = str_starts_with($location, 'file://') ? substr($location, 7) : $location;
        if ($this->storageBasePath !== '' && !str_starts_with($path, $this->storageBasePath)) {
            $path = $this->storageBasePath . '/' . ltrim($path, '/');
        }

        $real = realpath($path);
        if ($real === false) {
            return $path;
        }

        if ($this->storageBasePath !== '' && !str_starts_with($real, $this->storageBasePath)) {
            throw new RuntimeException('not_authorized');
        }

        return $real;
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

function inferBaseUrl(): string
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return sprintf('%s://%s', $scheme, $host);
}
