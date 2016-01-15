<?php

namespace JoseJwt\Random;

interface RandomGenerator
{
    /**
     * @param int $bytesLength
     *
     * @return string
     */
    public function get($bytesLength);
}
