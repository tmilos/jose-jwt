<?php

/*
 * This file is part of the jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace JoseJwt\Jws;

use JoseJwt\Error\JoseJwtException;
use JoseJwt\Util\StringUtils;

class PlainText implements JwsAlgorithm
{
    /**
     * @param string $securedInput
     * @param string $key
     *
     * @return string
     */
    public function sign($securedInput, $key)
    {
        return '';
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
        if (null != $key) {
            throw new JoseJwtException('Plaintext algorithm expects key to be null');
        }

        return StringUtils::length($signature) === 0;
    }
}
