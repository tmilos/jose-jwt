<?php

namespace JoseJwt\Jwe;

use JoseJwt\Util\ParameterBag;

class JweEncryptionCollection
{
    /** @var ParameterBag */
    private $bag;

    public function __construct()
    {
        $this->bag = new ParameterBag();
    }

    /**
     * @param string       $id
     * @param JweEncryption $algorithm
     *
     * @return JweEncryptionCollection
     */
    public function add($id, JweEncryption $algorithm)
    {
        $this->bag->set($id, $algorithm);

        return $this;
    }

    /**
     * @param string $id
     *
     * @return JweEncryption
     */
    public function get($id)
    {
        return $this->bag->get($id, null);
    }

    /**
     * @param string $id
     *
     * @return bool
     */
    public function has($id)
    {
        return $this->bag->has($id);
    }

    /**
     * @return JweEncryption[] id => JweEncryption
     */
    public function all()
    {
        return $this->bag->all();
    }
}
