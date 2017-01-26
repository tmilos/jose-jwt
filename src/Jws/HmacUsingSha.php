<?php

/*
 * This file is part of the tmilos/jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Tmilos\JoseJwt\Jws;

use Tmilos\JoseJwt\Error\JoseJwtException;

class HmacUsingSha implements JwsAlgorithm
{
    /** @var string */
    private $hashMethod;

    /**
     * @param string $hashMethod
     */
    public function __construct($hashMethod)
    {
        $this->hashMethod = $hashMethod;
    }

    /**
     * @param string $securedInput
     * @param string $key
     *
     * @return string
     */
    public function sign($securedInput, $key)
    {
        if (null === $key || trim($key) === '') {
            throw new JoseJwtException('Hmac key can not be empty');
        }

        return hash_hmac($this->hashMethod, $securedInput, $key, true);
    }

    /**
     * @param string $signature
     * @param string $securedInput
     * @param string $key
     *
     * @return bool
     */
    public function verify($signature, $securedInput, $key)
    {
        if (null == $key || trim($key) === '') {
            throw new JoseJwtException('Hmac key can not be empty');
        }

        $calculatedSignature = hash_hmac($this->hashMethod, $securedInput, $key, true);

        return $signature === $calculatedSignature;
    }
}
