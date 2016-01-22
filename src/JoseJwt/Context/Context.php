<?php

namespace JoseJwt\Context;

use JoseJwt\Json\JsonMapper;
use JoseJwt\Jwe\JweAlgorithmCollection;
use JoseJwt\Jwe\JweEncryptionCollection;
use JoseJwt\Jws\JwsAlgorithmCollection;
use JoseJwt\Random\RandomGenerator;

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
