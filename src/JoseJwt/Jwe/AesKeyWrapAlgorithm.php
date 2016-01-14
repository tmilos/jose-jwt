<?php

namespace JoseJwt\Jwe;

use JoseJwt\Error\JoseJwtException;

class AesKeyWrapAlgorithm implements JweAlgorithm
{
    /** @var int */
    private $kekLengthBits;

    /** @var string */
    private $wrapperClass;

    /** @var array */
    private static $wrapperMap = [
        128 => 'AESKW\A128KW',
        192 => 'use AESKW\A192KW',
        256 => 'use AESKW\A256KW',
    ];

    /**
     * @param int $keySize
     */
    public function __construct($keySize)
    {
        $this->kekLengthBits = $keySize;
        if (false === array_key_exists($keySize, self::$wrapperMap)) {
            throw new JoseJwtException(sprintf('Invalid kek key size "%s"', $keySize));
        } else {
            $this->wrapperClass = self::$wrapperMap[$keySize];
        }
    }

    /**
     * @param int             $cekSizeBits
     * @param string|resource $kek
     * @param array           $header
     *
     * @return array [cek, encryptedCek]
     */
    public function wrapNewKey($cekSizeBits, $kek, array $header)
    {
        $kekLen = strlen($kek);
        if ($kekLen * 8 != $this->kekLengthBits) {
            throw new JoseJwtException(sprintf('AesKeyWrap management algorithm expected key of size %s bits, but was given %s bits', $this->kekLengthBits, $kekLen*8));
        }
        if ($cekSizeBits % 8 != 0) {
            throw new JoseJwtException('CekSizeBits must be divisible by 8');
        }

        $cek = openssl_random_pseudo_bytes($cekSizeBits/8);

        $encryptedCek = $this->aesWrap($kek, $cek);

        return [$cek, $encryptedCek];
    }

    /**
     * @param string $encryptedCek
     * @param string $kek
     * @param int    $cekSizeBits
     * @param array  $header
     *
     * @return string
     */
    public function unwrap($encryptedCek, $kek, $cekSizeBits, array $header)
    {
        $kekLen = strlen($kek);
        if ($kekLen * 8 != $this->kekLengthBits) {
            throw new JoseJwtException(sprintf('AesKeyWrap management algorithm expected key of size %s bits, but was given %s bits', $this->kekLengthBits, $kekLen*8));
        }

        return $this->aesUnwrap($kek, $encryptedCek);
    }

    /**
     * @param string $kek
     * @param string $key
     *
     * @return string
     */
    private function aesWrap($kek, $key)
    {
        return call_user_func([$this->wrapperClass, 'wrap'], $kek, $key);
    }

    /**
     * @param string $kek
     * @param string $wrappedKey
     *
     * @return string
     */
    private function aesUnwrap($kek, $wrappedKey)
    {
        return call_user_func([$this->wrapperClass, 'unwrap'], $kek, $wrappedKey);
    }
}
