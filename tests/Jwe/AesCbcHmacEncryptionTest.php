<?php

namespace Tests\Tmilos\JoseJwt\Jwe;

use Tmilos\JoseJwt\Error\IntegrityException;
use Tmilos\JoseJwt\Error\JoseJwtException;
use Tmilos\JoseJwt\Jwe\AesCbcHmacEncryption;
use Tmilos\JoseJwt\Jwe\JweEncryption;
use Tmilos\JoseJwt\Jws\JwsAlgorithm;
use Tmilos\JoseJwt\Random\RandomGenerator;

class AesCbcHmacEncryptionTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_with_int_jws_algorithm_and_random_generator()
    {
        new AesCbcHmacEncryption(128, $this->getJwsAlgorithmMock(), $this->getRandomGeneratorMock());
    }

    public function test_implements_jwe_encryption()
    {
        $reflection = new \ReflectionClass(AesCbcHmacEncryption::class);
        $this->assertTrue($reflection->implementsInterface(JweEncryption::class));
    }

    public function key_size_cek_provider()
    {
        return [
            [256, str_pad('', 256/8, 'x'), null, null],
            [384, str_pad('', 384/8, 'x'), null, null],
            [512, str_pad('', 512/8, 'x'), null, null],
            [256, str_pad('', 512/8, 'x'), JoseJwtException::class, 'AES-CBC with HMAC algorithm expected key of size 256 bits, but was given 512 bits'],
            [384, str_pad('', 256/8, 'x'), JoseJwtException::class, 'AES-CBC with HMAC algorithm expected key of size 384 bits, but was given 256 bits'],
            [512, str_pad('', 128/8, 'x'), JoseJwtException::class, 'AES-CBC with HMAC algorithm expected key of size 512 bits, but was given 128 bits'],
        ];
    }

    /**
     * @dataProvider key_size_cek_provider
     */
    public function test_throws_on_encrypt_with_cek_length_not_equal_to_key_size_given_in_constructor($keySize, $cek, $expectedException, $expectedExceptionMessage)
    {
        if ($expectedException) {
            if (method_exists($this, 'expectException')) {
                $this->expectException($expectedException);
                $this->expectExceptionMessage($expectedExceptionMessage);
            } else {
                $this->setExpectedException($expectedException, $expectedExceptionMessage);
            }
        }

        $encryption = new AesCbcHmacEncryption($keySize, $this->getJwsAlgorithmMock(), $randomGenerator = $this->getRandomGeneratorMock());
        $randomGenerator->expects($this->any())->method('get')->willReturnCallback(function($len) {
            return str_pad('', $len, 'x');
        });

        $encryption->encrypt('foo', 'plain', $cek);
    }

    /**
     * @dataProvider key_size_cek_provider
     */
    public function test_throws_on_decrypt_with_cek_length_not_equal_to_key_size_given_in_constructor($keySize, $cek, $expectedException, $expectedExceptionMessage)
    {
        if (!$expectedException) {
            $expectedException = IntegrityException::class;
            $expectedExceptionMessage = 'Authentication tag does not match';
        }
        if (method_exists($this, 'expectException')) {
            $this->expectException($expectedException);
            $this->expectExceptionMessage($expectedExceptionMessage);
        } else {
            $this->setExpectedException($expectedException, $expectedExceptionMessage);
        }

        $encryption = new AesCbcHmacEncryption($keySize, $this->getJwsAlgorithmMock(), $randomGenerator = $this->getRandomGeneratorMock());

        $encryption->decrypt('foo', $cek, '123', 'abababa', 'auth');
    }

    /**
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage AES-CBC with HMAC encryption expected key of even number size
     */
    public function test_throws_on_encrypt_when_cek_size_not_even()
    {
        $encryption = new AesCbcHmacEncryption(264, $this->getJwsAlgorithmMock(), $randomGenerator = $this->getRandomGeneratorMock());

        $encryption->encrypt('foo', 'plain', str_pad('', 33, 'x'));
    }

    /**
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage AES-CBC with HMAC encryption expected key of even number size
     */
    public function test_throws_on_decrypt_when_cek_size_not_even()
    {
        $encryption = new AesCbcHmacEncryption(264, $this->getJwsAlgorithmMock(), $randomGenerator = $this->getRandomGeneratorMock());

        $encryption->decrypt('foo', str_pad('', 33, 'x'), '123', 'ananana', 'auth');
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|JwsAlgorithm
     */
    private function getJwsAlgorithmMock()
    {
        return $this->getMockBuilder(JwsAlgorithm::class)->getMock();
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|RandomGenerator
     */
    private function getRandomGeneratorMock()
    {
        return $this->getMockBuilder(RandomGenerator::class)->getMock();
    }
}
