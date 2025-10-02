<?php
declare(strict_types=1);

namespace App\Tests;

use PDO;
use PHPUnit\Framework\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected PDO $pdo;

    protected function setUp(): void
    {
        parent::setUp();
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->createSchema();
    }

    private function createSchema(): void
    {
        $this->pdo->exec('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, avatar_uuid TEXT UNIQUE, password_hash TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)');
        $this->pdo->exec('CREATE TABLE assets (id TEXT PRIMARY KEY, type TEXT, location TEXT, content_type TEXT, filename TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)');
        $this->pdo->exec('CREATE TABLE permissions (user_id INTEGER, asset_id TEXT, can_fetch INTEGER DEFAULT 1, PRIMARY KEY (user_id, asset_id))');
        $this->pdo->exec('CREATE TABLE auth_tokens (token TEXT PRIMARY KEY, user_id INTEGER, expires_at TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)');
    }
}
