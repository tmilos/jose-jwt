<?php

namespace Tests\Tmilos\JoseJwt\Jwe;

use Tmilos\JoseJwt\Jwe\DirectAlgorithm;
use Tmilos\JoseJwt\Jwe\JweAlgorithm;

class DirectAlgorithmTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_wout_arguments()
    {
        new DirectAlgorithm();
    }

    public function test_implements_jwe_algorithm()
    {
        $reflection = new \ReflectionClass(DirectAlgorithm::class);
        $this->assertTrue($reflection->implementsInterface(JweAlgorithm::class));
    }

    /**
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Direct algorithm expects empty content encryption key
     */
    public function test_throws_on_unwrap_with_non_empty_encrypted_cek()
    {
        $algorithm = new DirectAlgorithm();
        $algorithm->unwrap('abababa', 'key', 10, []);
    }
}
