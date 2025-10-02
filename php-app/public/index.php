<?php
declare(strict_types=1);

use App\Auth;
use App\Authorize;
use App\RateLimiter;
use App\Signer;
use App\Validator;
use Dotenv\Dotenv;
use InvalidArgumentException;
use RuntimeException;

require __DIR__ . '/../vendor/autoload.php';

if (file_exists(__DIR__ . '/../.env')) {
    $dotenv = Dotenv::createImmutable(dirname(__DIR__));
    $dotenv->load();
}

$forceHttps = filter_var($_ENV['FORCE_HTTPS'] ?? 'true', FILTER_VALIDATE_BOOL);
if ($forceHttps) {
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    if (!$isHttps) {
        jsonError(400, 'https_required', 'HTTPS is required for this endpoint');
    }
}

$rateLimiter = new RateLimiter((int)($_ENV['RATE_LIMIT_PER_MINUTE'] ?? '60'));
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

try {
    if ($path === '/api/auth' && $method === 'POST') {
        $rateLimiter->assertWithinLimit('auth:' . clientKey());
        requireSharedSecret();
        $payload = decodeJsonBody();
        Validator::ensureAuthPayload($payload);

        $auth = new Auth();
        $result = $auth->authenticate($payload['avatar_uuid'], $payload['password']);
        jsonResponse($result, $result['ok'] ? 200 : 401);
    }

    if ($path === '/api/authorize' && $method === 'POST') {
        $rateLimiter->assertWithinLimit('authorize:' . clientKey());
        requireSharedSecret();
        $payload = decodeJsonBody();
        Validator::ensureAuthorizePayload($payload);

        $authorize = new Authorize();
        $result = $authorize->authorize($payload['token'], $payload['request'], $payload['id']);
        $status = $result['ok'] ? 200 : mapErrorToStatus($result['error_code'] ?? 'internal');
        jsonResponse($result, $status);
    }

    if ($path === '/api/download' && $method === 'GET') {
        $rateLimiter->assertWithinLimit('download:' . clientKey());
        $id = $_GET['id'] ?? '';
        $sig = $_GET['sig'] ?? '';
        $expires = isset($_GET['expires']) ? (int)$_GET['expires'] : 0;
        if (!Validator::isUuid($id)) {
            jsonError(400, 'invalid_id', 'The asset identifier is invalid');
        }

        if ($expires < time()) {
            jsonError(403, 'url_expired', 'Download link expired');
        }

        $signer = new Signer($_ENV['HMAC_SECRET'] ?? '');
        if (!$signer->isValidSignature($id, $expires, $sig)) {
            jsonError(403, 'invalid_signature', 'Signature validation failed');
        }

        $authorize = new Authorize();
        $download = $authorize->downloadAsset($id);
        if (!($download['ok'] ?? false)) {
            $code = $download['error_code'] ?? 'internal_error';
            jsonError(mapErrorToStatus($code), $code, $download['message'] ?? 'Download failed');
        }

        header('Content-Type: ' . $download['content_type']);
        header('Content-Disposition: attachment; filename="' . addslashes($download['filename']) . '"');
        header('X-Correlation-Id: ' . correlationId());
        readfile($download['path']);
        exit;
    }

    jsonError(404, 'not_found', 'Unknown endpoint');
} catch (InvalidArgumentException $e) {
    jsonError(400, $e->getMessage(), 'Validation failed');
} catch (RuntimeException $e) {
    $code = $e->getMessage();
    if ($code === 'rate_limited') {
        jsonError(429, 'rate_limited', 'Rate limit exceeded');
    }

    jsonError(mapErrorToStatus($code), $code, 'Request rejected');
} catch (Throwable $e) {
    $debug = filter_var($_ENV['APP_DEBUG'] ?? 'false', FILTER_VALIDATE_BOOL);
    $message = $debug ? $e->getMessage() : 'Server error';
    jsonError(500, 'internal_error', $message, $e->getCode(), $e);
}

function decodeJsonBody(): array
{
    $body = (string)file_get_contents('php://input');
    if ($body === '') {
        return [];
    }

    $data = json_decode($body, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        jsonError(400, 'invalid_json', 'Malformed JSON body');
    }

    return $data ?? [];
}

function clientKey(): string
{
    $addr = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    return (string)$addr;
}

function requireSharedSecret(): void
{
    $expected = $_ENV['SHARED_SECRET'] ?? '';
    if ($expected === '') {
        return;
    }

    $provided = $_SERVER['HTTP_X_SHARED_SECRET'] ?? '';
    if ($provided === '' || !hash_equals($expected, $provided)) {
        jsonError(401, 'auth_failed', 'Shared secret mismatch');
    }
}

function mapErrorToStatus(string $code): int
{
    return match ($code) {
        'invalid_payload', 'invalid_request', 'invalid_id', 'invalid_uuid', 'invalid_password' => 400,
        'auth_failed' => 401,
        'not_authorized' => 403,
        'not_found' => 404,
        'rate_limited' => 429,
        default => 400,
    };
}

function jsonResponse(array $data, int $status): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    header('X-Correlation-Id: ' . correlationId());
    echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function jsonError(int $status, string $code, string $message, int $internalCode = 0, ?Throwable $throwable = null): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    header('X-Correlation-Id: ' . correlationId());
    $payload = [
        'ok' => false,
        'error_code' => $code,
        'message' => $message,
        'correlation_id' => correlationId(),
    ];

    if ($throwable !== null && filter_var($_ENV['APP_DEBUG'] ?? 'false', FILTER_VALIDATE_BOOL)) {
        $payload['trace'] = $throwable->getTraceAsString();
    }

    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function correlationId(): string
{
    static $id = null;
    if ($id === null) {
        $headerId = $_SERVER['HTTP_X_CORRELATION_ID'] ?? '';
        $id = $headerId !== '' ? $headerId : bin2hex(random_bytes(8));
    }

    return $id;
}
