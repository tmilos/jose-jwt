<?php

namespace JoseJwt;

use JoseJwt\Json\JsonMapper;
use JoseJwt\Jwe\JweAlgorithm;
use JoseJwt\Jwe\JweEncryption;
use JoseJwt\Jws\JwsAlgorithm;

class Configuration
{
    /** @var JsonMapper|null */
    private $jsonMapper;

    /**
     * @var JwsAlgorithm[]
     */
    private $hashAlgorithms = [];

    /**
     * @var JweAlgorithm[]
     */
    private $jweAlgorithms = [];

    /**
     * @var JweEncryption[]
     */
    private $jweEncryptions = [];

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
     * @return Configuration
     */
    public function setJsonMapper(JsonMapper $jsonMapper = null)
    {
        $this->jsonMapper = $jsonMapper;

        return $this;
    }

    /**
     * @return JwsAlgorithm[]
     */
    public function getAllHashAlgorithms()
    {
        return $this->hashAlgorithms;
    }

    /**
     * @param string $id
     *
     * @return JwsAlgorithm|null
     */
    public function getHashAlgorithm($id)
    {
        return @$this->hashAlgorithms[$id];
    }

    /**
     * @param string $id
     *
     * @return bool
     */
    public function hasHashAlgorithm($id)
    {
        return isset($this->hashAlgorithms[$id]);
    }

    /**
     * @param string       $id
     * @param JwsAlgorithm $algorithm
     *
     * @return Configuration
     */
    public function addHashAlgorithm($id, JwsAlgorithm $algorithm)
    {
        $this->hashAlgorithms[$id] = $algorithm;

        return $this;
    }

    /**
     * @param string $id
     *
     * @return JweAlgorithm|null
     */
    public function getJweAlgorithm($id)
    {
        return $this->jweAlgorithms[$id];
    }

    /**
     * @param string       $id
     * @param JweAlgorithm $algorithm
     *
     * @return Configuration
     */
    public function addJweAlgorithm($id, JweAlgorithm $algorithm)
    {
        $this->jweAlgorithms[$id] = $algorithm;

        return $this;
    }

    /**
     * @param string $id
     *
     * @return JweEncryption|null
     */
    public function getJweEncryption($id)
    {
        return @$this->jweEncryptions[$id];
    }

    /**
     * @param string        $id
     * @param JweEncryption $encryption
     *
     * @return Configuration
     */
    public function addJweEncryption($id, JweEncryption $encryption)
    {
        $this->jweEncryptions[$id] = $encryption;

        return $this;
    }
}
