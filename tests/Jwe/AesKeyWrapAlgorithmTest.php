<?php

namespace Tests\Tmilos\JoseJwt\Jwe;

use Tmilos\JoseJwt\Error\JoseJwtException;
use Tmilos\JoseJwt\Jwe\AesKeyWrapAlgorithm;
use Tmilos\JoseJwt\Random\RandomGenerator;

class AesKeyWrapAlgorithmTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_with_key_size_and_random_generator()
    {
        new AesKeyWrapAlgorithm(128, $this->getRandomGeneratorMock());
    }

    public function construct_key_size_provider()
    {
        return [
            [1, JoseJwtException::class, 'Invalid kek key size "1"'],
            [64, JoseJwtException::class, 'Invalid kek key size "64"'],
            [512, JoseJwtException::class, 'Invalid kek key size "512"'],
            [128, null, null],
            [192, null, null],
            [256, null, null],
        ];
    }

    /**
     * @dataProvider construct_key_size_provider
     */
    public function test_construct_key_size($keySize, $expectedException, $expectedExceptionMessage)
    {
        if ($expectedException) {
            if (method_exists($this, 'expectException')) {
                $this->expectException($expectedException);
                $this->expectExceptionMessage($expectedExceptionMessage);
            } else {
                $this->setExpectedException($expectedException, $expectedExceptionMessage);
            }
        }

        new AesKeyWrapAlgorithm($keySize, $this->getRandomGeneratorMock());
    }

    public function key_size_kek_provider()
    {
        return [
            [128, str_pad('', 128/8, 'x'), null, null],
            [192, str_pad('', 192/8, 'x'), null, null],
            [256, str_pad('', 256/8, 'x'), null, null],

            [128, str_pad('', 256/8, 'x'), JoseJwtException::class, 'AesKeyWrap management algorithm expected key of size 128 bits, but was given 256 bits'],
            [192, str_pad('', 128/8, 'x'), JoseJwtException::class, 'AesKeyWrap management algorithm expected key of size 192 bits, but was given 128 bits'],
            [256, str_pad('', 512/8, 'x'), JoseJwtException::class, 'AesKeyWrap management algorithm expected key of size 256 bits, but was given 512 bits'],
        ];
    }

    /**
     * @dataProvider key_size_kek_provider
     */
    public function test_throws_on_wrap_new_key_when_kek_length_does_not_match_key_size_given_to_constructor($keySize, $kek, $expectedException, $expectedExceptionMessage)
    {
        if ($expectedException) {
            if (method_exists($this, 'expectException')) {
                $this->expectException($expectedException);
                $this->expectExceptionMessage($expectedExceptionMessage);
            } else {
                $this->setExpectedException($expectedException, $expectedExceptionMessage);
            }
        }

        $cekSizeBits = 512;

        $algorithm = new AesKeyWrapAlgorithm($keySize, $randomGenerator = $this->getRandomGeneratorMock());
        $randomGenerator->expects($this->any())->method('get')->willReturn(str_pad('', $cekSizeBits/8, 'x'));

        $algorithm->wrapNewKey($cekSizeBits, $kek, []);
    }

    /**
     * @dataProvider key_size_kek_provider
     */
    public function test_throws_on_unwrap_when_kek_length_does_not_match_key_size_given_to_constructor($keySize, $kek, $expectedException, $expectedExceptionMessage)
    {
        if (!$expectedException) {
            $expectedException = class_exists('Assert\InvalidArgumentException') ? 'Assert\InvalidArgumentException' : 'RuntimeException';
            $expectedExceptionMessage = 'Bad data';
        }
        if (method_exists($this, 'expectException')) {
            $this->expectException($expectedException);
            $this->expectExceptionMessage($expectedExceptionMessage);
        } else {
            $this->setExpectedException($expectedException, $expectedExceptionMessage);
        }

        $cekSizeBits = 512;
        $encryptedCek = '123';

        $algorithm = new AesKeyWrapAlgorithm($keySize, $randomGenerator = $this->getRandomGeneratorMock());

        $algorithm->unwrap($encryptedCek, $kek, $cekSizeBits, []);
    }

    /**
     * @expectedException \Tmilos\JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage CekSizeBits must be divisible by 8
     */
    public function test_throws_on_wrap_new_key_when_cek_size_bits_not_divisible_by_8()
    {
        $algorithm = new AesKeyWrapAlgorithm(128, $this->getRandomGeneratorMock());
        $algorithm->wrapNewKey(130, str_pad('', 128/8, 'x'), []);
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|RandomGenerator
     */
    private function getRandomGeneratorMock()
    {
        return $this->getMockBuilder(RandomGenerator::class)->getMock();
    }
}
