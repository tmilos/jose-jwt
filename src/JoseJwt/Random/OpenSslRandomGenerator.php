<?php

namespace JoseJwt\Random;

class OpenSslRandomGenerator implements RandomGenerator
{
    /**
     * @param int $bytesLength
     *
     * @return string
     */
    public function get($bytesLength)
    {
        return openssl_random_pseudo_bytes($bytesLength);
    }
}
