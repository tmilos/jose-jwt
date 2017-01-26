<?php

namespace Tests\Tmilos\JoseJwt;

use Tmilos\JoseJwt\Jws\JwsAlgorithm;
use Tmilos\JoseJwt\Jwt;
use Tmilos\JoseJwt\Util\UrlSafeB64Encoder;

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

    /**
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Unknown algorithm "foo_algo"
     */
    public function test_encode_throws_on_unknown_algorithm()
    {
        JWT::encode($this->context, 'payload', 'key', 'foo_algo');
    }

    public function empty_token_provider()
    {
        return [
            [''],
            [' '],
            ['       '],
            [null],
        ];
    }

    /**
     * @dataProvider empty_token_provider
     *
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Incoming token expected to be in compact serialization form, but is empty
     */
    public function test_decode_throws_on_empty_token($token)
    {
        JWT::decode($this->context, $token, 'key');
    }

    /**
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Invalid header
     */
    public function test_decode_throws_on_invalid_header()
    {
        JWT::decode($this->context, 'aaaa.bbbb.ccc', 'key');
    }

    /**
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Invalid algorithm "foo_algo"
     */
    public function test_decode_throws_on_invalid_algorithm()
    {
        $header = ['alg'=>'foo_algo'];
        $headerEncoded = UrlSafeB64Encoder::encode(json_encode($header));

        JWT::decode($this->context, $headerEncoded.'.bbbb.ccc', 'key');
    }

    /**
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Invalid signature
     */
    public function test_decode_throws_integrity_exception()
    {
        $headerEncoded = UrlSafeB64Encoder::encode(json_encode(['alg'=>JwsAlgorithm::HS256]));
        JWT::decode($this->context, $headerEncoded.'.bbb.ccc', 'key');
    }

    /**
     * @dataProvider empty_token_provider
     *
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Incoming token expected to be in compact serialization form, but is empty
     */
    public function test_header_throws_on_empty_token($token)
    {
        JWT::header($token);
    }

    public function invalid_jwt_token_provider()
    {
        return [
            ['aaaaa'],
            ['aaaaa.bbbbb'],
            ['aaaaa.bbbbb.ccc.ddd'],
            ['aaaaa.bbbbb.ccc.ddd.eee.ffff'],
        ];
    }

    /**
     * @dataProvider invalid_jwt_token_provider
     *
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Invalid JWT
     */
    public function test_header_throws_on_invalid_jwt_token($token)
    {
        JWT::header($token);
    }

    /**
     * @dataProvider invalid_jwt_token_provider
     *
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Invalid header
     */
    public function test_header_throws_on_invalid_header()
    {
        JWT::header('aaa.bbb.ccc');
    }

    /**
     * @dataProvider empty_token_provider
     *
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Incoming token expected to be in compact serialization form, but is empty
     */
    public function test_payload_throws_on_empty_token($token)
    {
        JWT::payload($token);
    }

    /**
     * @dataProvider invalid_jwt_token_provider
     *
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Invalid JWT
     */
    public function test_payload_throws_on_invalid_jwt_token($token)
    {
        JWT::payload($token);
    }
}
