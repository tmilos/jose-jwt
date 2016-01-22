<?php

namespace JoseJwt\Context;

use JoseJwt\Json\JsonMapper;
use JoseJwt\Jwe\JweAlgorithmCollection;
use JoseJwt\Jwe\JweEncryptionCollection;
use JoseJwt\Jws\JwsAlgorithmCollection;

class DefaultContext implements Context
{
    /** @var JsonMapper|null */
    private $jsonMapper;

    /** @var JwsAlgorithmCollection */
    private $jwsAlgorithms;

    /** @var JweAlgorithmCollection */
    private $jweAlgorithms;

    /** @var JweEncryptionCollection */
    private $jweEncryptions;

    /**
     */
    public function __construct()
    {
        $this->jwsAlgorithms = new JwsAlgorithmCollection();
        $this->jweAlgorithms = new JweAlgorithmCollection();
        $this->jweEncryptions = new JweEncryptionCollection();
    }

    /**
     * @return JsonMapper|null
     */
    public function jsonMapper()
    {
        return $this->jsonMapper;
    }

    /**
     * @return JwsAlgorithmCollection
     */
    public function jwsAlgorithms()
    {
        return $this->jwsAlgorithms;
    }

    /**
     * @return JweAlgorithmCollection
     */
    public function jweAlgorithms()
    {
        return $this->jweAlgorithms;
    }

    /**
     * @return JweEncryptionCollection
     */
    public function jweEncryptions()
    {
        return $this->jweEncryptions;
    }

    /**
     * @param JsonMapper|null $jsonMapper
     *
     * @return DefaultContext
     */
    public function setJsonMapper(JsonMapper $jsonMapper = null)
    {
        $this->jsonMapper = $jsonMapper;

        return $this;
    }
}
