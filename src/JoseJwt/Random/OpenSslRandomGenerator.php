<?php

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
