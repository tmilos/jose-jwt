<?php

namespace Tests\Tmilos\JoseJwt\Mock;

class PayloadJsonSerializable implements \JsonSerializable
{
    /** @var string */
    private $a;

    /**
     * @param string $a
     */
    public function __construct($a = null)
    {
        $this->a = $a;
    }

    /**
     * @return string
     */
    public function getA()
    {
        return $this->a;
    }

    /**
     * @param string $a
     */
    public function setA($a)
    {
        $this->a = $a;
    }

    /**
     * @return array
     */
    public function jsonSerialize()
    {
        return ['a'=>$this->a];
    }
}
