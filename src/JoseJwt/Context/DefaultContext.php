<?php

namespace JoseJwt\Context;

use JoseJwt\Json\JsonMapper;
use JoseJwt\Jwe\JweAlgorithmCollection;
use JoseJwt\Jwe\JweEncryptionCollection;
use JoseJwt\Jws\JwsAlgorithmCollection;
use JoseJwt\Random\RandomGenerator;

class DefaultContext implements Context
{
    /** @var JsonMapper|null */
    private $jsonMapper;

    /** @var RandomGenerator */
    private $randomGenerator;

    /** @var JwsAlgorithmCollection */
    private $jwsAlgorithms;

    /** @var JweAlgorithmCollection */
    private $jweAlgorithms;

    /** @var JweEncryptionCollection */
    private $jweEncryptions;

    /**
     * @param RandomGenerator $randomGenerator
     */
    public function __construct(RandomGenerator $randomGenerator)
    {
        $this->randomGenerator = $randomGenerator;
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
     * @return RandomGenerator
     */
    public function randomGenerator()
    {
        return $this->randomGenerator();
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
     * @return JsonMapper|null
     */
    public function getJsonMapper()
    {
        return $this->jsonMapper;
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
