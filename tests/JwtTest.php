<?php

namespace JoseJwt\Tests;

use JoseJwt\Configuration;
use JoseJwt\Factory;
use JoseJwt\Jws\JwsAlgorithm;
use JoseJwt\Jwt;

class JwtTest extends \PHPUnit_Framework_TestCase
{
    /** @var Configuration */
    private $configuration;

    private $payload = [
        'sub' => 'mr.x@contoso.com',
        'exp' => 1300819380,
    ];

    private $extraHeader = [
        'foo' => 'bar',
    ];

    private $tokens = [
        'none' =>  'eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwiZm9vIjoiYmFyIn0.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.',
        'hs256' => 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.j-zS0EuiwCsVlFUKzAaNYsYkETom9bBtEqmkSiKDqrg',
        'hs384' => 'eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.f6eGKPC3fCS6lRQ3O7eHbRhv4D9cSJ5tGZS9vbcPIKrYDIzic0hBLH9__seOqZkY',
        'hs512' => 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.j2pU3ic1aQubmxG8MuekAObFOFRmeKJ0uBhaU8dJQR5jIq55fPj83keqQ6b4BpsAlG5OhwPk4aUqcs7vOtZ4Aw',
        'rs256' => 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.XW7oSrjnyF57T4jUz0HEVrCG-sKddIZPvBZriK7p6ZMYy_KUyahzYhnr9UXQUMFBQw59kvTmay0nUJwAhuF3zRBmV-1yT2J_gH8BUeVwGTm2AWo4d-Sbkrds9_oQMg6OWucWTcoL3j4FmS8Q0pxXZae-dkA4ZfJN3vitGcsKX9OzlkgyJ6uFR1tKZA4bmkxS8kDyw7H28EAtl2B5PUCS-xPxivvXGIN6ZtTwpWwzF4AJ1fHmL-Y-wN3LSpMG4WNEnpK3L-GEkPz5yPP7cF1pr-rIKwkokrpJH4JIxur9his4UrinONg8Kdj-lwTPFbM0QySEnikMX76x-ksPFQuZrg',
        'rs384' => 'eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.BbcpQNheeXFu2Pnp5tfcRYuDW-pu-N-81KLwu7aw7mqsrQPxi0tcMDb7dqiWZ9r-c5YKGyWrK2gVX66c3-XVhOfjhlJCBBf3Tn8I8z_QCNmAcz0jPU0-l3PzRHnJB8j94Hhw1e40JMA5_5LSLA3eyhQIxGAJaYjHI4blT_-KRA6KgTB7d_Pj64YoB7-D8dhNTKSQMRJm_C_BbjZrxjS7dsfQ9KmBqeM6WsGm2fehLuRY6cCGKv83PXxBWTFAeJ8bWLa5Ena_k6cDu8wDKl0IdEKtaCDedwMcdRgcJxjs8Tu36nZClS606tRfy21P11Pa9Pki91e0l8pafpoEnkrM3Q',
        'rs512' => 'eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCIsImZvbyI6ImJhciJ9.eyJzdWIiOiJtci54QGNvbnRvc28uY29tIiwiZXhwIjoxMzAwODE5MzgwfQ.XcuZL-qa0QLEryFlkTk-0JvFY5Pkqzrw-4xtRPk285L4gqxe8jOhTYI4UkueZkfO2xcdzQCBwZu-u7ceoFWCS-gL2G1bglhJARclsJmxdBA7r_Whzq4AUmOpcF0Oz-cA27ZlpbVD2n-qOPC6aNNubj0DguKPCIrFDfmbcJbcdmpVQPbBO8yyRkH08uDLGEy9v2hnabkrxvZOquRueZg1CzuMghTMsGIct8w1ktV7qD5_8ABS8eU4MIUIooIsmzOOCUBZ1tCQ_rOFvbh6GLyxn3t6dDd85g-u5d-zEM8OlqXGkgqKXhxuMcpu9R7IJJLZTvy-P9ezj7uTpd_Lnhe7wQ',
    ];

    protected function setUp()
    {
        parent::setUp();

        $factory = new Factory();
        $this->configuration = $factory->getConfiguration();
    }

    public function test_encode_none()
    {
        $token = Jwt::encode($this->configuration, $this->payload, null, JwsAlgorithm::NONE, $this->extraHeader);
        $this->assertEquals($this->tokens['none'], $token);
    }

    public function test_encode_HS256()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getSecret(), JwsAlgorithm::HS256, $this->extraHeader);
        $this->assertEquals($this->tokens['hs256'], $token);
    }

    public function test_encode_HS384()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getSecret(), JwsAlgorithm::HS384, $this->extraHeader);
        $this->assertEquals($this->tokens['hs384'], $token);
    }

    public function test_encode_HS512()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getSecret(), JwsAlgorithm::HS512, $this->extraHeader);
        $this->assertEquals($this->tokens['hs512'], $token);
    }

    public function test_encode_RS256()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getRsaPrivateKey(), JwsAlgorithm::RS256, $this->extraHeader);
        $this->assertEquals($this->tokens['rs256'], $token);
    }

    public function test_encode_RS384()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getRsaPrivateKey(), JwsAlgorithm::RS384, $this->extraHeader);
        $this->assertEquals($this->tokens['rs384'], $token);
    }

    public function test_encode_RS512()
    {
        $token = Jwt::encode($this->configuration, $this->payload, $this->getRsaPrivateKey(), JwsAlgorithm::RS512, $this->extraHeader);
        $this->assertEquals($this->tokens['rs512'], $token);
    }

    public function test_decode_none()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['none'], null);
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_HS256()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['hs256'], $this->getSecret());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_HS384()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['hs384'], $this->getSecret());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_HS512()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['hs512'], $this->getSecret());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_RS256()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['rs256'], $this->getRsaPublicKey());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_RS384()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['rs384'], $this->getRsaPublicKey());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_decode_RS512()
    {
        $payload = Jwt::decode($this->configuration, $this->tokens['rs512'], $this->getRsaPublicKey());
        $this->assertEquals($this->payload, $payload);
    }

    public function test_header_none()
    {
        $header = Jwt::header($this->tokens['none']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::NONE,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_HS256()
    {
        $header = Jwt::header($this->tokens['hs256']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::HS256,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_HS384()
    {
        $header = Jwt::header($this->tokens['hs384']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::HS384,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_HS512()
    {
        $header = Jwt::header($this->tokens['hs512']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::HS512,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_RS256()
    {
        $header = Jwt::header($this->tokens['rs256']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::RS256,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_RS384()
    {
        $header = Jwt::header($this->tokens['rs384']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::RS384,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_header_RS512()
    {
        $header = Jwt::header($this->tokens['rs512']);
        $this->assertEquals([
            'alg' => JwsAlgorithm::RS512,
            'typ' => 'JWT',
            'foo' => 'bar',
        ], $header);
    }

    public function test_payload_none()
    {
        $payload = JWT::payload($this->tokens['none']);
        $this->assertEquals($this->payload, $payload);
    }

    public function test_payload_HS256()
    {
        $payload = JWT::payload($this->tokens['hs256']);
        $this->assertEquals($this->payload, $payload);
    }

    public function test_payload_RS256()
    {
        $payload = JWT::payload($this->tokens['rs256']);
        $this->assertEquals($this->payload, $payload);
    }

    /**
     * @return string
     */
    private function getSecret()
    {
        return pack('C*', 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234);
    }

    /**
     * @return resource
     */
    private function getRsaPublicKey()
    {
        $crt = openssl_x509_read(file_get_contents(__DIR__.'/../resources/a.crt'));
        $publicKey = openssl_get_publickey($crt);

        return $publicKey;
    }

    /**
     * @return resource
     */
    private function getRsaPrivateKey()
    {
        $key = openssl_get_privatekey(file_get_contents(__DIR__.'/../resources/a.key'));
        if (false === $key) {
            throw new \LogicException('Unable to load RSA private key');
        }

        return $key;
    }
}
