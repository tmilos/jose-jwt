<?php

namespace JoseJwt\Tests\Jwe;

use JoseJwt\Jwe\AesCbcHmacEncryption;

class AesCbcHmacEncryptionTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_with_int_jws_algorithm_and_random_generator()
    {
        new AesCbcHmacEncryption(128, $this->getJwsAlgorithmMock(), $this->getRandomGeneratorMock());
    }

    public function test_implements_jwe_encryption()
    {
        $reflection = new \ReflectionClass('JoseJwt\Jwe\AesCbcHmacEncryption');
        $this->assertTrue($reflection->implementsInterface('JoseJwt\Jwe\JweEncryption'));
    }

    public function key_size_cek_provider()
    {
        return [
            [256, str_pad('', 256/8, 'x'), null, null],
            [384, str_pad('', 384/8, 'x'), null, null],
            [512, str_pad('', 512/8, 'x'), null, null],
            [256, str_pad('', 512/8, 'x'), 'JoseJwt\Error\JoseJwtException', 'AES-CBC with HMAC algorithm expected key of size 256 bits, but was given 512 bits'],
            [384, str_pad('', 256/8, 'x'), 'JoseJwt\Error\JoseJwtException', 'AES-CBC with HMAC algorithm expected key of size 384 bits, but was given 256 bits'],
            [512, str_pad('', 128/8, 'x'), 'JoseJwt\Error\JoseJwtException', 'AES-CBC with HMAC algorithm expected key of size 512 bits, but was given 128 bits'],
        ];
    }

    /**
     * @dataProvider key_size_cek_provider
     */
    public function test_throws_on_encrypt_with_cek_length_not_equal_to_key_size_given_in_constructor($keySize, $cek, $expectedException, $expectedExceptionMessage)
    {
        if ($expectedException) {
            $this->setExpectedException($expectedException, $expectedExceptionMessage);
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
        if ($expectedException) {
            $this->setExpectedException($expectedException, $expectedExceptionMessage);
        } else {
            $this->setExpectedException('JoseJwt\Error\IntegrityException', 'Authentication tag does not match');
        }

        $encryption = new AesCbcHmacEncryption($keySize, $this->getJwsAlgorithmMock(), $randomGenerator = $this->getRandomGeneratorMock());

        $encryption->decrypt('foo', $cek, '123', 'abababa', 'auth');
    }

    /**
     * @expectedException \JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage AES-CBC with HMAC encryption expected key of even number size
     */
    public function test_throws_on_encrypt_when_cek_size_not_even()
    {
        $encryption = new AesCbcHmacEncryption(264, $this->getJwsAlgorithmMock(), $randomGenerator = $this->getRandomGeneratorMock());

        $encryption->encrypt('foo', 'plain', str_pad('', 33, 'x'));
    }

    /**
     * @expectedException \JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage AES-CBC with HMAC encryption expected key of even number size
     */
    public function test_throws_on_decrypt_when_cek_size_not_even()
    {
        $encryption = new AesCbcHmacEncryption(264, $this->getJwsAlgorithmMock(), $randomGenerator = $this->getRandomGeneratorMock());

        $encryption->decrypt('foo', str_pad('', 33, 'x'), '123', 'ananana', 'auth');
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\JoseJwt\Jws\JwsAlgorithm
     */
    private function getJwsAlgorithmMock()
    {
        return $this->getMock('JoseJwt\Jws\JwsAlgorithm');
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\JoseJwt\Random\RandomGenerator
     */
    private function getRandomGeneratorMock()
    {
        return $this->getMock('JoseJwt\Random\RandomGenerator');
    }
}
