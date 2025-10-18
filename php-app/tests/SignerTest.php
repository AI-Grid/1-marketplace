<?php
declare(strict_types=1);

namespace App\Tests;

use App\Signer;

final class SignerTest extends TestCase
{
    public function testSignatureRoundTrip(): void
    {
        $signer = new Signer('secret');
        $expires = time() + 600;
        $sig = $signer->sign('123e4567-e89b-12d3-a456-426614174000', $expires);

        self::assertTrue($signer->isValidSignature('123e4567-e89b-12d3-a456-426614174000', $expires, $sig));
        self::assertFalse($signer->isValidSignature('123e4567-e89b-12d3-a456-426614174001', $expires, $sig));
    }
}
