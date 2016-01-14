<?php

namespace JoseJwt\Tests;

use JoseJwt\Jws\JwsAlgorithm;
use JoseJwt\Jwt;

class JwtTest extends AbstractTestBase
{

    public function test_encode_none()
    {
        $token = Jwt::encode($this->configuration, $this->payload, null, JwsAlgorithm::NONE, $this->extraHeader);
        $this->assertEquals($this->tokens['NONE'], $token);
    }

    public function test_encode_HS256()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getSecret(), JwsAlgorithm::HS256, $this->extraHeader);
        $this->assertEquals($this->tokens['HS256'], $token);
    }

    public function test_encode_HS384()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getSecret(), JwsAlgorithm::HS384, $this->extraHeader);
        $this->assertEquals($this->tokens['HS384'], $token);
    }

    public function test_encode_HS512()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getSecret(), JwsAlgorithm::HS512, $this->extraHeader);
        $this->assertEquals($this->tokens['HS512'], $token);
    }

    public function test_encode_RS256()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getRsaPrivateKey(), JwsAlgorithm::RS256, $this->extraHeader);
        $this->assertEquals($this->tokens['RS256'], $token);
    }

    public function test_encode_RS384()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getRsaPrivateKey(), JwsAlgorithm::RS384, $this->extraHeader);
        $this->assertEquals($this->tokens['RS384'], $token);
    }

    public function test_encode_RS512()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getRsaPrivateKey(), JwsAlgorithm::RS512, $this->extraHeader);
        $this->assertEquals($this->tokens['RS512'], $token);
    }

    public function test_decode_none()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['NONE'], null);
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_HS256()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['HS256'], $this->getSecret());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_HS384()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['HS384'], $this->getSecret());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_HS512()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['HS512'], $this->getSecret());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_RS256()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['RS256'], $this->getRsaPublicKey());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_RS384()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['RS384'], $this->getRsaPublicKey());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_RS512()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['RS512'], $this->getRsaPublicKey());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_header_none()
    {
        $header = Jwt::header($this->tokens['NONE']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::NONE,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_HS256()
    {
        $header = Jwt::header($this->tokens['HS256']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::HS256,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_HS384()
    {
        $header = Jwt::header($this->tokens['HS384']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::HS384,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_HS512()
    {
        $header = Jwt::header($this->tokens['HS512']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::HS512,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_RS256()
    {
        $header = Jwt::header($this->tokens['RS256']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::RS256,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_RS384()
    {
        $header = Jwt::header($this->tokens['RS384']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::RS384,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_RS512()
    {
        $header = Jwt::header($this->tokens['RS512']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::RS512,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_payload_none()
    {
        $payload = JWT::payload($this->tokens['NONE']);
        $this->assertEquals($this->payload, $payload);
    }

    public function test_payload_HS256()
    {
        $payload = JWT::payload($this->tokens['HS256']);
        $this->assertEquals($this->payload, $payload);
    }

    public function test_payload_RS256()
    {
        $payload = JWT::payload($this->tokens['RS256']);
        $this->assertEquals($this->payload, $payload);
    }
}
