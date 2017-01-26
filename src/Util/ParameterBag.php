<?php

/*
 * This file is part of the tmilos/jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Tmilos\JoseJwt\Util;

class ParameterBag implements \IteratorAggregate, \Countable
{
    /**
     * @var array
     */
    protected $parameters;

    /**
     * @param array $parameters
     */
    public function __construct(array $parameters = array())
    {
        $this->parameters = $parameters;
    }

    /**
     * @return array
     */
    public function all()
    {
        return $this->parameters;
    }

    /**
     * @return array
     */
    public function keys()
    {
        return array_keys($this->parameters);
    }

    /**
     * @param array $parameters
     *
     * @return ParameterBag
     */
    public function add(array $parameters = array())
    {
        $this->parameters = array_replace($this->parameters, $parameters);

        return $this;
    }

    /**
     * @param string $key
     * @param mixed  $value
     *
     * @return ParameterBag
     */
    public function set($key, $value)
    {
        $this->parameters[$key] = $value;

        return $this;
    }

    /**
     * @param string $key
     * @param mixed  $default
     *
     * @return mixed
     */
    public function get($key, $default = null)
    {
        return array_key_exists($key, $this->parameters) ? $this->parameters[$key] : $default;
    }

    /**
     * @param string $key
     *
     * @return bool
     */
    public function has($key)
    {
        return array_key_exists($key, $this->parameters);
    }

    /**
     * @param string $key
     *
     * @return ParameterBag
     */
    public function remove($key)
    {
        unset($this->parameters[$key]);

        return $this;
    }

    /**
     * @return \ArrayIterator
     */
    public function getIterator()
    {
        return new \ArrayIterator($this->parameters);
    }

    /**
     * @return int
     */
    public function count()
    {
        return count($this->parameters);
    }
}
