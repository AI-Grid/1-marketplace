<?php
declare(strict_types=1);

namespace App;

use RuntimeException;

final class Signer
{
    private string $secret;

    public function __construct(string $secret)
    {
        if ($secret === '') {
            throw new RuntimeException('HMAC secret must not be empty');
        }

        $this->secret = $secret;
    }

    public function sign(string $id, int $expiresAt): string
    {
        return hash_hmac('sha256', $id . ':' . $expiresAt, $this->secret);
    }

    public function isValidSignature(string $id, int $expiresAt, string $signature): bool
    {
        if ($signature === '') {
            return false;
        }

        $expected = $this->sign($id, $expiresAt);
        return hash_equals($expected, $signature);
    }
}
