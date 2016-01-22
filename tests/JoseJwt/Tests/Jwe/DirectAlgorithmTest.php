<?php

namespace JoseJwt\Tests\Jwe;

use JoseJwt\Jwe\DirectAlgorithm;
use JoseJwt\Jwe\JweAlgorithm;

class DirectAlgorithmTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_wout_arguments()
    {
        new DirectAlgorithm();
    }

    public function test_implements_jwe_algorithm()
    {
        $reflection = new \ReflectionClass('JoseJwt\Jwe\DirectAlgorithm');
        $this->assertTrue($reflection->implementsInterface('JoseJwt\Jwe\JweAlgorithm'));
    }

    /**
     * @expectedException \JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Direct algorithm expects empty content encryption key
     */
    public function test_throws_on_unwrap_with_non_empty_encrypted_cek()
    {
        $algorithm = new DirectAlgorithm();
        $algorithm->unwrap('abababa', 'key', 10, []);
    }
}
