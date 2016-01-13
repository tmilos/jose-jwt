<?php

namespace JoseJwt\Util;

class UrlSafeB64Encoder 
{
    /**
     * @param string $data
     *
     * @return string
     */
    public static function encode($data)
    {
        $b64 = base64_encode($data);
        $b64 = str_replace(
            array('+', '/', '\r', '\n', '='),
            array('-', '_'),
            $b64
        );

        return $b64;
    }
    /**
     * @param string $b64
     *
     * @return string
     */
    public static function decode($b64)
    {
        $b64 = str_replace(
            array('-', '_'),
            array('+', '/'),
            $b64
        );

        return base64_decode($b64);
    }
}
