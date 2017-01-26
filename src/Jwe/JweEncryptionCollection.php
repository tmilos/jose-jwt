<?php

/*
 * This file is part of the tmilos/jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Tmilos\JoseJwt\Jwe;

use Tmilos\JoseJwt\Util\ParameterBag;

class JweEncryptionCollection
{
    /** @var ParameterBag */
    private $bag;

    public function __construct()
    {
        $this->bag = new ParameterBag();
    }

    /**
     * @param string        $id
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
