<?php

namespace JoseJwt\Jws;

use JoseJwt\Util\ParameterBag;

class JwsAlgorithmCollection
{
    /** @var ParameterBag */
    private $bag;

    public function __construct()
    {
        $this->bag = new ParameterBag();
    }

    /**
     * @param string       $id
     * @param JwsAlgorithm $algorithm
     *
     * @return JwsAlgorithmCollection
     */
    public function add($id, JwsAlgorithm $algorithm)
    {
        $this->bag->set($id, $algorithm);

        return $this;
    }

    /**
     * @param string $id
     *
     * @return JwsAlgorithm
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
     * @return JwsAlgorithm[] id => JwsAlgorithm
     */
    public function all()
    {
        return $this->bag->all();
    }
}
