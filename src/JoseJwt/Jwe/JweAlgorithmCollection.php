<?php

/*
 * This file is part of the jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace JoseJwt\Jwe;

use JoseJwt\Util\ParameterBag;

class JweAlgorithmCollection
{
    /** @var ParameterBag */
    private $bag;

    public function __construct()
    {
        $this->bag = new ParameterBag();
    }

    /**
     * @param string       $id
     * @param JweAlgorithm $algorithm
     *
     * @return JweAlgorithmCollection
     */
    public function add($id, JweAlgorithm $algorithm)
    {
        $this->bag->set($id, $algorithm);

        return $this;
    }

    /**
     * @param string $id
     *
     * @return JweAlgorithm
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
     * @return JweAlgorithm[] id => JwsAlgorithm
     */
    public function all()
    {
        return $this->bag->all();
    }
}
