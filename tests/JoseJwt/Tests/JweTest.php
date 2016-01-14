<?php

namespace JoseJwt\Tests;

use JoseJwt\Jwe;

class JweTest extends AbstractTestBase
{
    public function test_direct_encode()
    {
        $token = Jwe::encode($this->configuration, $this->payload, $this->getSecret(256), Jwe\JweAlgorithm::DIR, Jwe\JweEncryption::A128CBC_HS256, $this->extraHeader);
        $this->assertEquals($this->tokens['DIR - A128CBC-HS256'], $token);
    }
}
