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

interface JwsAlgorithm
{
    const NONE = 'none';
    const HS256 = 'HS256';
    const HS384 = 'HS384';
    const HS512 = 'HS512';
    const RS256 = 'RS256';
    const RS384 = 'RS384';
    const RS512 = 'RS512';

    /**
     * @param string $securedInput
     * @param string $key
     *
     * @return string
     */
    public function sign($securedInput, $key);

    /**
     * @param string $signature
     * @param string $securedInput
     * @param string $key
     *
     * @return bool
     */
    public function verify($signature, $securedInput, $key);
}
