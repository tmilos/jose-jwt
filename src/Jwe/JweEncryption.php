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

interface JweEncryption
{
    const A128CBC_HS256 = 'A128CBC-HS256';
    const A192CBC_HS384 = 'A192CBC-HS384';
    const A256CBC_HS512 = 'A256CBC-HS512';

    /**
     * @return int
     */
    public function getKeySize();

    /**
     * @param string          $aad
     * @param string          $plainText
     * @param string|resource $cek
     *
     * @return array [iv, cipherText, authTag]
     */
    public function encrypt($aad, $plainText, $cek);

    /**
     * @param string          $aad
     * @param string|resource $cek
     * @param string          $iv
     * @param string          $cipherText
     * @param string          $authTag
     *
     * @return string
     */
    public function decrypt($aad, $cek, $iv, $cipherText, $authTag);
}
