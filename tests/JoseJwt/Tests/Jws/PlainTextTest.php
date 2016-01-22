<?php

namespace JoseJwt\Tests\Jws;

use JoseJwt\Jws\PlainText;

class PlainTextTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_wout_arguments()
    {
        new PlainText();
    }

    /**
     * @expectedException \JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Plaintext algorithm expects key to be null
     */
    public function test_throws_on_verify_with_not_null_key()
    {
        $algorithm = new PlainText();
        $algorithm->verify('sign', 'foo', 'aaa');
    }
}
