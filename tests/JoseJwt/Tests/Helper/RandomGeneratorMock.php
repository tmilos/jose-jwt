<?php

namespace JoseJwt\Tests\Helper;

use JoseJwt\Random\RandomGenerator;
use JoseJwt\Util\UrlSafeB64Encoder;

class RandomGeneratorMock implements RandomGenerator
{
    /** @var array */
    private $sequence = [];

    /**
     * @param int $bytesLength
     *
     * @return string
     */
    public function get($bytesLength)
    {
        if (false === array_key_exists($bytesLength, $this->sequence)) {
            throw new \InvalidArgumentException(sprintf('There are no predefined random sequences for %s bytes length', $bytesLength));
        }

        $arr = $this->sequence[$bytesLength];
        if (empty($arr)) {
            throw new \LogicException(sprintf('Predefined random sequence for %s bytes length is exhausted'));
        }

        $value = array_shift($arr);

        $this->sequence[$bytesLength] = $arr;

        return $value;
    }

    /**
     * @param string $value
     * @param bool   $raw
     *
     * @return RandomGeneratorMock
     */
    public function add($value, $raw = false)
    {
        if (is_array($value)) {
            array_unshift($value, 'C*');
            $value = call_user_func_array('pack', $value);
            $raw = true;
        }
        if (false === $raw) {
            $value = UrlSafeB64Encoder::decode($value);
        }

        $len = strlen($value);
        if (false === array_key_exists($len, $this->sequence)) {
            $this->sequence[$len] = [];
        }
        $this->sequence[$len][] = $value;

        return $this;
    }
}
