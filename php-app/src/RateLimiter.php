<?php
declare(strict_types=1);

namespace App;

use RuntimeException;

final class RateLimiter
{
    private int $limitPerMinute;
    private string $storageDir;

    public function __construct(int $limitPerMinute)
    {
        if ($limitPerMinute <= 0) {
            throw new RuntimeException('Rate limit must be positive');
        }

        $this->limitPerMinute = $limitPerMinute;
        $this->storageDir = sys_get_temp_dir() . '/content-rate';
        if (!is_dir($this->storageDir) && !mkdir($this->storageDir, 0770, true) && !is_dir($this->storageDir)) {
            throw new RuntimeException('Unable to initialise rate limiter storage');
        }
    }

    public function assertWithinLimit(string $key): void
    {
        $bucket = $this->storageDir . '/' . sha1($key);
        $now = time();
        $windowStart = $now - 60;

        $entries = [];
        if (file_exists($bucket)) {
            $raw = file_get_contents($bucket);
            $entries = $raw ? array_filter(array_map('intval', explode('\n', trim($raw)))) : [];
        }

        $entries = array_filter($entries, static fn(int $ts) => $ts >= $windowStart);
        if (count($entries) >= $this->limitPerMinute) {
            throw new RuntimeException('rate_limited');
        }

        $entries[] = $now;
        file_put_contents($bucket, implode("\n", $entries), LOCK_EX);
    }
}
