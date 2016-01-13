<?php

namespace JoseJwt;

use JoseJwt\Error\IntegrityException;
use JoseJwt\Error\JoseJwtException;
use JoseJwt\Util\StringUtils;
use JoseJwt\Util\UrlSafeB64Encoder;

class Jwt
{
    /**
     * @param Configuration   $configuration
     * @param array|object    $payload
     * @param string|resource $key
     * @param string          $jwsAlgorithm
     * @param array           $extraHeaders
     *
     * @return string
     */
    public static function encode(Configuration $configuration, $payload, $key, $jwsAlgorithm, $extraHeaders = [])
    {
        $header = array_merge([
            'alg' => '',
            'typ' => 'JWT',
        ], $extraHeaders);

        $hashAlgorithm = $configuration->getHashAlgorithm($jwsAlgorithm);
        if (null == $hashAlgorithm) {
            throw new JoseJwtException(sprintf('Unknown algorithm "%s"', $jwsAlgorithm));
        }

        $header['alg'] = $jwsAlgorithm;

        $payloadString = StringUtils::payload2string($payload, $configuration->getJsonMapper());

        $signingInput = implode('.', [
            UrlSafeB64Encoder::encode(json_encode($header)),
            UrlSafeB64Encoder::encode($payloadString),
        ]);

        $signature = $hashAlgorithm->sign($signingInput, $key);
        $signature = UrlSafeB64Encoder::encode($signature);

        return $signingInput.'.'.$signature;
    }

    /**
     * @param Configuration   $configuration
     * @param string          $token
     * @param string|resource $key
     *
     * @return array
     */
    public static function decode(Configuration $configuration, $token, $key)
    {
        if (null === $token || trim($token) === '') {
            throw new JoseJwtException('Incoming token expected to be in compact serialization form, but is empty');
        }

        $parts = explode('.', $token);
        if (count($parts) != 3) {
            throw new JoseJwtException('Invalid JWT');
        }

        $decodedParts = [];
        foreach ($parts as $part) {
            $decodedParts[] = UrlSafeB64Encoder::decode($part);
        }
        $header = json_decode($decodedParts[0], true);
        if (null == $header) {
            throw new JoseJwtException('Invalid header');
        }

        if (count($parts) == 5) {
            // encrypted JWT
            throw new \LogicException('Not implemented');
        } else {
            // signed or plain JWT
            $signedInput = $parts[0].'.'.$parts[1];
            $algorithmId = $header['alg'];
            $algorithm = $configuration->getHashAlgorithm($algorithmId);
            if (null === $algorithm) {
                throw new JoseJwtException(sprintf('Invalid algorithm "%s"', $algorithmId));
            }

            if (false === $algorithm->verify($decodedParts[2], $signedInput, $key)) {
                throw new IntegrityException('Invalid signature');
            }

            return json_decode($decodedParts[1], true);
        }
    }

    /**
     * @param $token
     *
     * @return array
     */
    public static function header($token)
    {
        if (null === $token || trim($token) === '') {
            throw new JoseJwtException('Incoming token expected to be in compact serialization form, but is empty');
        }

        $parts = explode('.', $token);
        if (count($parts) != 3) {
            throw new JoseJwtException('Invalid JWT');
        }

        $header = json_decode(UrlSafeB64Encoder::decode($parts[0]), true);
        if (null == $header) {
            throw new JoseJwtException('Invalid header');
        }

        return $header;
    }

    /**
     * @param $token
     *
     * @return array
     */
    public static function payload($token)
    {
        if (null === $token || trim($token) === '') {
            throw new JoseJwtException('Incoming token expected to be in compact serialization form, but is empty');
        }

        $parts = explode('.', $token);
        if (count($parts) != 3) {
            throw new JoseJwtException('Invalid JWT');
        }

        $payload = json_decode(UrlSafeB64Encoder::decode($parts[1]), true);
        if (null == $payload) {
            throw new JoseJwtException('Invalid payload');
        }

        return $payload;
    }
}
