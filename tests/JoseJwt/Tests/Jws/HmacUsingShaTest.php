<?php

namespace JoseJwt\Tests\Jws;

use JoseJwt\Jws\HmacUsingSha;
use JoseJwt\Jws\JwsAlgorithm;

class HmacUsingShaTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_with_hash_method_name()
    {
        new HmacUsingSha('sha1');
    }

    public function test_implements_jws_algorithm()
    {
        $reflectionClass = new \ReflectionClass('JoseJwt\Jws\HmacUsingSha');
        $this->assertTrue($reflectionClass->implementsInterface('JoseJwt\Jws\JwsAlgorithm'));
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
     * @expectedException \JoseJwt\Error\JoseJwtException
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
     * @expectedException \JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Hmac key can not be empty
     */
    public function test_throws_on_verify_with_empty_key($key)
    {
        $algorithm = new HmacUsingSha('sha1');
        $algorithm->verify('sign', 'foo', $key);
    }
}
