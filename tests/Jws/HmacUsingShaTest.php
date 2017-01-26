<?php

namespace Tests\Tmilos\JoseJwt\Jws;

use Tmilos\JoseJwt\Jws\HmacUsingSha;
use Tmilos\JoseJwt\Jws\JwsAlgorithm;

class HmacUsingShaTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_with_hash_method_name()
    {
        new HmacUsingSha('sha1');
    }

    public function test_implements_jws_algorithm()
    {
        $reflectionClass = new \ReflectionClass(HmacUsingSha::class);
        $this->assertTrue($reflectionClass->implementsInterface(JwsAlgorithm::class));
    }

    public function empty_key_provider()
    {
        return [
            [''],
            [null],
        ];
    }

    /**
     * @dataProvider empty_key_provider
     *
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Hmac key can not be empty
     */
    public function test_throws_on_sign_with_empty_key($key)
    {
        $algorithm = new HmacUsingSha('sha1');
        $algorithm->sign('foo', $key);
    }

    /**
     * @dataProvider empty_key_provider
     *
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Hmac key can not be empty
     */
    public function test_throws_on_verify_with_empty_key($key)
    {
        $algorithm = new HmacUsingSha('sha1');
        $algorithm->verify('sign', 'foo', $key);
    }
}
