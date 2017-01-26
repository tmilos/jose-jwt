<?php

/*
 * This file is part of the tmilos/jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Tmilos\JoseJwt\Jwe;

use Tmilos\JoseJwt\Error\IntegrityException;
use Tmilos\JoseJwt\Error\JoseJwtException;
use Tmilos\JoseJwt\Jws\JwsAlgorithm;
use Tmilos\JoseJwt\Random\RandomGenerator;
use Tmilos\JoseJwt\Util\StringUtils;

class AesCbcHmacEncryption implements JweEncryption
{
    /** @var JwsAlgorithm */
    private $hashAlgorithm;

    /** @var int */
    private $keySize;

    /** @var RandomGenerator */
    private $randomGenerator;

    /**
     * @param int             $keySize
     * @param JwsAlgorithm    $hashAlgorithm
     * @param RandomGenerator $randomGenerator
     */
    public function __construct($keySize, JwsAlgorithm $hashAlgorithm, RandomGenerator $randomGenerator)
    {
        $this->keySize = $keySize;
        $this->hashAlgorithm = $hashAlgorithm;
        $this->randomGenerator = $randomGenerator;
    }

    /**
     * @return int
     */
    public function getKeySize()
    {
        return $this->keySize;
    }

    /**
     * @param string          $aad
     * @param string          $plainText
     * @param string|resource $cek
     *
     * @return array [iv, cipherText, authTag]
     */
    public function encrypt($aad, $plainText, $cek)
    {
        $cekLen = StringUtils::length($cek);
        if ($cekLen * 8 != $this->keySize) {
            throw new JoseJwtException(sprintf('AES-CBC with HMAC algorithm expected key of size %s bits, but was given %s bits', $this->keySize, $cekLen * 8));
        }
        if ($cekLen % 2 != 0) {
            throw new JoseJwtException('AES-CBC with HMAC encryption expected key of even number size');
        }

        $hmacKey = StringUtils::substring($cek, 0, $cekLen / 2);
        $aesKey = StringUtils::substring($cek, $cekLen / 2, $cekLen / 2);

        $method = sprintf('AES-%d-CBC', $this->keySize / 2);
        $ivLen = openssl_cipher_iv_length($method);
        $iv = $this->randomGenerator->get($ivLen);
        $cipherText = openssl_encrypt($plainText, $method, $aesKey, true, $iv);

        $authTag = $this->computeAuthTag($aad, $iv, $cipherText, $hmacKey);

        return [$iv, $cipherText, $authTag];
    }

    /**
     * @param string          $aad
     * @param string|resource $cek
     * @param string          $iv
     * @param string          $cipherText
     * @param string          $authTag
     *
     * @return string
     */
    public function decrypt($aad, $cek, $iv, $cipherText, $authTag)
    {
        $cekLen = StringUtils::length($cek);
        if ($cekLen * 8 != $this->keySize) {
            throw new JoseJwtException(sprintf('AES-CBC with HMAC algorithm expected key of size %s bits, but was given %s bits', $this->keySize, $cekLen * 8));
        }
        if ($cekLen % 2 != 0) {
            throw new JoseJwtException('AES-CBC with HMAC encryption expected key of even number size');
        }

        $hmacKey = StringUtils::substring($cek, 0, $cekLen / 2);
        $aesKey = StringUtils::substring($cek, $cekLen / 2);

        $expectedAuthTag = $this->computeAuthTag($aad, $iv, $cipherText, $hmacKey);
        if (false === StringUtils::equals($expectedAuthTag, $authTag)) {
            throw new IntegrityException('Authentication tag does not match');
        }

        $method = sprintf('AES-%d-CBC', $this->keySize / 2);
        $plainText = openssl_decrypt($cipherText, $method, $aesKey, true, $iv);

        return $plainText;
    }

    /**
     * @param $aad
     * @param $iv
     * @param $cipherText
     * @param $hmacKey
     *
     * @return string
     */
    private function computeAuthTag($aad, $iv, $cipherText, $hmacKey)
    {
        $aadLen = StringUtils::length($aad);
        $max32bit = 2147483647;
        $hmacInput = implode('', [
            $aad,
            $iv,
            $cipherText,
            pack('N2', ($aadLen / $max32bit) * 8, ($aadLen % $max32bit) * 8),
        ]);
        $authTag = $this->hashAlgorithm->sign($hmacInput, $hmacKey);
        $authTagLen = StringUtils::length($authTag);
        $authTag = StringUtils::substring($authTag, 0, $authTagLen / 2);

        return $authTag;
    }
}
