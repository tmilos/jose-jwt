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

class RsaUsingSha implements JwsAlgorithm
{
    /** @var string */
    private $signatureAlgorithm;

    /**
     * @param string $signatureAlgorithm
     */
    public function __construct($signatureAlgorithm)
    {
        $this->signatureAlgorithm = $signatureAlgorithm;
    }

    /**
     * @param string $securedInput
     * @param string $key
     *
     * @return string
     */
    public function sign($securedInput, $key)
    {
        if (false === openssl_sign($securedInput, $signature, $key, $this->signatureAlgorithm)) {
            throw new JoseJwtException('Unable to sign data: '.openssl_error_string());
        }

        return $signature;
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
        return openssl_verify($securedInput, $signature, $key, $this->signatureAlgorithm);
    }
}
