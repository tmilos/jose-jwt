<?php

namespace JoseJwt\Jws;

use JoseJwt\Error\JoseJwtException;

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