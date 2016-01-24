<?php

/*
 * This file is part of the jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace JoseJwt\Context;

use JoseJwt\Json\JsonMapper;
use JoseJwt\Jwe\JweAlgorithmCollection;
use JoseJwt\Jwe\JweEncryptionCollection;
use JoseJwt\Jws\JwsAlgorithmCollection;

interface Context
{
    /**
     * @return JsonMapper|null
     */
    public function jsonMapper();

    /**
     * @return JwsAlgorithmCollection
     */
    public function jwsAlgorithms();

    /**
     * @return JweAlgorithmCollection
     */
    public function jweAlgorithms();

    /**
     * @return JweEncryptionCollection
     */
    public function jweEncryptions();
}
