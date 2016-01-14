<?php

namespace JoseJwt\Jwe;

interface JweAlgorithm
{
    const RSA1_5 = 'RSA1_5';
    const RSA_OAEP = 'RSA-OAEP';
    const A128KW = 'A128KW';
    const A192KW = 'A192KW';
    const A256KW = 'A256KW';
    const DIR = 'dir';

    /**
     * @param int             $cekSizeBits
     * @param string|resource $kek
     * @param array           $header
     *
     * @return array [cek, encryptedCek]
     */
    public function wrapNewKey($cekSizeBits, $kek, array $header);

    /**
     * @param string          $encryptedCek
     * @param string|resource $key
     * @param int             $cekSizeBits
     * @param array           $header
     *
     * @return string
     */
    public function unwrap($encryptedCek, $key, $cekSizeBits, array $header);
}
