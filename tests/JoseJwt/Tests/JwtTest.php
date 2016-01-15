<?php

namespace JoseJwt\Tests;

use JoseJwt\Jws\JwsAlgorithm;
use JoseJwt\Jwt;

class JwtTest extends AbstractTestBase
{
    public function encode_provider()
    {
        return [
            ['NONE', null, JwsAlgorithm::NONE],
            ['HS256', $this->getSecret(256), JwsAlgorithm::HS256],
            ['HS384', $this->getSecret(256), JwsAlgorithm::HS384],
            ['HS512', $this->getSecret(256), JwsAlgorithm::HS512],
            ['RS256', $this->getRsaPrivateKey(), JwsAlgorithm::RS256],
            ['RS384', $this->getRsaPrivateKey(), JwsAlgorithm::RS384],
            ['RS512', $this->getRsaPrivateKey(), JwsAlgorithm::RS512],
        ];
    }

    /**
     * @dataProvider encode_provider
     */
    public function test_encode($tokenName, $key, $algorithm)
    {
        $token = Jwt::encode($this->context, $this->payload, $key, $algorithm, $this->extraHeader);
        $this->assertEquals($this->tokens[$tokenName], $token);
    }


    public function decode_provider()
    {
        return [
            [$this->tokens['NONE'], null],
            [$this->tokens['HS256'], $this->getSecret(256)],
            [$this->tokens['HS384'], $this->getSecret(256)],
            [$this->tokens['HS512'], $this->getSecret(256)],
            [$this->tokens['RS256'], $this->getRsaPublicKey()],
            [$this->tokens['RS384'], $this->getRsaPublicKey()],
            [$this->tokens['RS512'], $this->getRsaPublicKey()],
        ];
    }

    /**
     * @dataProvider decode_provider
     */
    public function test_decode($token, $key)
    {
        $payload = Jwt::decode($this->context, $token, $key);
        $this->assertEquals($this->payload, $payload);

    }

    public function header_provider()
    {
        return [
            [$this->tokens['NONE'], JwsAlgorithm::NONE],
            [$this->tokens['HS256'], JwsAlgorithm::HS256],
            [$this->tokens['HS384'], JwsAlgorithm::HS384],
            [$this->tokens['HS512'], JwsAlgorithm::HS512],
            [$this->tokens['HS512'], JwsAlgorithm::HS512],
            [$this->tokens['RS256'], JwsAlgorithm::RS256],
            [$this->tokens['RS384'], JwsAlgorithm::RS384],
            [$this->tokens['RS512'], JwsAlgorithm::RS512],
        ];
    }

    /**
     * @dataProvider header_provider
     */
    public function test_header($token, $algorithm)
    {
        $header = Jwt::header($token);
        $this->assertEquals([
            'alg' => $algorithm,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function payload_provider()
    {
        return [
            [$this->tokens['NONE']],
            [$this->tokens['HS256']],
            [$this->tokens['HS384']],
            [$this->tokens['HS512']],
            [$this->tokens['RS256']],
            [$this->tokens['RS384']],
            [$this->tokens['RS512']],
        ];
    }

    /**
     * @dataProvider payload_provider
     */
    public function test_payload($token)
    {
        $payload = JWT::payload($token);
        $this->assertEquals($this->payload, $payload);
    }
}
