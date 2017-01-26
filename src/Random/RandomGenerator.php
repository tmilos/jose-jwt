<?php

/*
 * This file is part of the tmilos/jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Tmilos\JoseJwt\Random;

interface RandomGenerator
{
    /**
     * @param int $bytesLength
     *
     * @return string
     */
    public function get($bytesLength);
}
