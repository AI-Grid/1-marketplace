<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

$_ENV['HMAC_SECRET'] = $_ENV['HMAC_SECRET'] ?? 'test-secret';
$_ENV['SHARED_SECRET'] = $_ENV['SHARED_SECRET'] ?? 'shared-secret';
$_ENV['SIGNED_URL_TTL_SECONDS'] = $_ENV['SIGNED_URL_TTL_SECONDS'] ?? '600';
$_ENV['DOWNLOAD_STRATEGY'] = $_ENV['DOWNLOAD_STRATEGY'] ?? 'signed_url';
$_ENV['APP_BASE_URL'] = $_ENV['APP_BASE_URL'] ?? 'https://example.test';
$_ENV['TOKEN_TTL_SECONDS'] = $_ENV['TOKEN_TTL_SECONDS'] ?? '600';
