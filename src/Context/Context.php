<?php

/*
 * This file is part of the tmilos/jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Tmilos\JoseJwt\Context;

use Tmilos\JoseJwt\Json\JsonMapper;
use Tmilos\JoseJwt\Jwe\JweAlgorithmCollection;
use Tmilos\JoseJwt\Jwe\JweEncryptionCollection;
use Tmilos\JoseJwt\Jws\JwsAlgorithmCollection;

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
