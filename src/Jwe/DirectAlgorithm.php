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

use Tmilos\JoseJwt\Error\JoseJwtException;

class DirectAlgorithm implements JweAlgorithm
{
    /**
     * @param int             $cekSizeBits
     * @param string|resource $kek
     * @param array           $header
     *
     * @return array [cek, encryptedCek]
     */
    public function wrapNewKey($cekSizeBits, $kek, array $header)
    {
        return [$kek, ''];
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
        if ($encryptedCek) {
            throw new JoseJwtException('Direct algorithm expects empty content encryption key');
        }

        return $key;
    }
}
