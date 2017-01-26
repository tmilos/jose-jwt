<?php

/*
 * This file is part of the tmilos/jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Tmilos\JoseJwt;

use Tmilos\JoseJwt\Context\Context;
use Tmilos\JoseJwt\Error\JoseJwtException;
use Tmilos\JoseJwt\Util\StringUtils;
use Tmilos\JoseJwt\Util\UrlSafeB64Encoder;

class Jwe
{
    private function __construct()
    {
    }

    /**
     * @param Context $context
     * @param         $payload
     * @param         $key
     * @param         $jweAlgorithm
     * @param         $jweEncryption
     * @param array   $extraHeaders
     *
     * @return string
     */
    public static function encode(Context $context, $payload, $key, $jweAlgorithm, $jweEncryption, array $extraHeaders = [])
    {
        if (empty($payload) || (is_string($payload) && trim($payload) == '')) {
            throw new JoseJwtException('Payload can not be empty');
        }
        $algorithm = $context->jweAlgorithms()->get($jweAlgorithm);
        if (null === $algorithm) {
            throw new JoseJwtException(sprintf('Invalid or unsupported algorithm "%s"', $jweAlgorithm));
        }
        $encryption = $context->jweEncryptions()->get($jweEncryption);
        if (null === $encryption) {
            throw new JoseJwtException(sprintf('Invalid or unsupported encryption "%s"', $jweEncryption));
        }

        $header = array_merge([
            'alg' => $jweAlgorithm,
            'enc' => $jweEncryption,
            'typ' => 'JWT',
        ], $extraHeaders);

        list($cek, $encryptedCek) = $algorithm->wrapNewKey($encryption->getKeySize(), $key, $header);

        $payloadString = StringUtils::payload2string($payload, $context->jsonMapper());

        $headerString = json_encode($header);
        $aad = UrlSafeB64Encoder::encode($headerString);
        $parts = $encryption->encrypt($aad, $payloadString, $cek);

        return implode('.', [
            UrlSafeB64Encoder::encode($headerString),
            UrlSafeB64Encoder::encode($encryptedCek),
            UrlSafeB64Encoder::encode($parts[0]),
            UrlSafeB64Encoder::encode($parts[1]),
            UrlSafeB64Encoder::encode($parts[2]),
        ]);
    }

    /**
     * @param Context         $context
     * @param string          $token
     * @param string|resource $key
     *
     * @return string
     */
    public static function decode(Context $context, $token, $key)
    {
        $parts = self::getParts($token);
        $decodedParts = self::decodeParts($parts);

        $headerString = $decodedParts[0];
        $encryptedCek = $decodedParts[1];
        $iv = $decodedParts[2];
        $cipherText = $decodedParts[3];
        $authTag = $decodedParts[4];

        $header = json_decode($headerString, true);
        if (null === $header) {
            throw new JoseJwtException('Invalid header');
        }

        $algorithm = $context->jweAlgorithms()->get($header['alg']);
        $encryption = $context->jweEncryptions()->get($header['enc']);

        $cek = $algorithm->unwrap($encryptedCek, $key, $encryption->getKeySize(), $header);
        $aad = $parts[0];

        $plainText = $encryption->decrypt($aad, $cek, $iv, $cipherText, $authTag);

        return $plainText;
    }

    /**
     * @param string $token
     *
     * @return string
     */
    public static function header($token)
    {
        $parts = self::getParts($token);
        $decodedParts = self::decodeParts($parts);

        $headerString = $decodedParts[0];

        $header = json_decode($headerString, true);
        if (null === $header) {
            throw new JoseJwtException('Invalid header');
        }

        return $header;
    }

    /**
     * @param array $parts [header, encryptedCek, iv, cipherText, authTag]
     *
     * @return array
     */
    private static function decodeParts(array $parts)
    {
        if (count($parts) != 5) {
            throw new JoseJwtException('Invalid JWE token');
        }

        $decodedParts = [];
        foreach ($parts as $part) {
            $decodedParts[] = UrlSafeB64Encoder::decode($part);
        }

        return $decodedParts;
    }

    /**
     * @param string $token
     *
     * @return array [header, encryptedCek, iv, cipherText, authTag]
     */
    private static function getParts($token)
    {
        if (empty($token) || trim($token) === '') {
            throw new JoseJwtException('Incoming token expected to be in compact serialization form, but is empty');
        }

        $parts = explode('.', $token);
        if (count($parts) != 5) {
            throw new JoseJwtException('Invalid JWE token');
        }

        return $parts;
    }
}
