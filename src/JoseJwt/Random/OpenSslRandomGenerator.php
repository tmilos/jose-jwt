<?php

/*
 * This file is part of the jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace JoseJwt\Random;

use JoseJwt\Error\JoseJwtException;

class OpenSslRandomGenerator implements RandomGenerator
{
    /**
     * @param int $bytesLength
     *
     * @return string
     */
    public function get($bytesLength)
    {
        $result = openssl_random_pseudo_bytes($bytesLength, $strong);
        if (false === $result || false === $strong) {
            throw new JoseJwtException('Unable to generate strong random sequence');
        }

        return $result;
    }
}
