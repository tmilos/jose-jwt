<?php

namespace JoseJwt\Jwe;

use JoseJwt\Error\JoseJwtException;

class RsaAlgorithm implements JweAlgorithm
{
    /** @var int */
    private $padding;

    /**
     * @param int $padding
     */
    public function __construct($padding)
    {
        $this->padding = $padding;
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
        $cek = openssl_random_pseudo_bytes(128);
        if (false == openssl_public_encrypt($cek, $cekEncrypted, $kek, $this->padding)) {
            throw new JoseJwtException('Unable to encrypt CEK');
        }

        return $cekEncrypted;
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
