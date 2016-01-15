<?php

namespace JoseJwt\Jwe;

use JoseJwt\Error\JoseJwtException;
use JoseJwt\Random\RandomGenerator;

class RsaAlgorithm implements JweAlgorithm
{
    /** @var int */
    private $padding;

    /** @var RandomGenerator */
    private $randomGenerator;

    /**
     * @param int             $padding
     * @param RandomGenerator $randomGenerator
     */
    public function __construct($padding, RandomGenerator $randomGenerator)
    {
        $this->padding = $padding;
        $this->randomGenerator = $randomGenerator;
    }

    /**
     * @param int             $cekSizeBits
     * @param string|resource $kek
     * @param array           $header
     *
     * @return array [cek, encryptedCek]
     */
    public function wrapNewKey($cekSizeBits, $kek, array $header)
    {
        $cek = $this->randomGenerator->get($cekSizeBits/8);
        if (false == openssl_public_encrypt($cek, $cekEncrypted, $kek, $this->padding)) {
            throw new JoseJwtException('Unable to encrypt CEK');
        }

        return [$cek, $cekEncrypted];
    }

    /**
     * @param string          $encryptedCek
     * @param string|resource $key
     * @param int             $cekSizeBits
     * @param array           $header
     *
     * @return string
     */
    public function unwrap($encryptedCek, $key, $cekSizeBits, array $header)
    {
        if (false == openssl_private_decrypt($encryptedCek, $cek, $key, $this->padding)) {
            throw new JoseJwtException('Unable to decrypt CEK');
        }

        return $cek;
    }
}
