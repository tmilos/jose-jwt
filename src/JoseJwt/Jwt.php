<?php

namespace JoseJwt;

use JoseJwt\Context\Context;
use JoseJwt\Error\IntegrityException;
use JoseJwt\Error\JoseJwtException;
use JoseJwt\Util\StringUtils;
use JoseJwt\Util\UrlSafeB64Encoder;

class Jwt
{
    private function __construct()
    {
    }

    /**
     * @param Context         $context
     * @param array|object    $payload
     * @param string|resource $key
     * @param string          $jwsAlgorithm
     * @param array           $extraHeaders
     *
     * @return string
     */
    public static function encode(Context $context, $payload, $key, $jwsAlgorithm, $extraHeaders = [])
    {
        $header = array_merge([
            'alg' => '',
            'typ' => 'JWT',
        ], $extraHeaders);

        $hashAlgorithm = $context->jwsAlgorithms()->get($jwsAlgorithm);
        if (null == $hashAlgorithm) {
            throw new JoseJwtException(sprintf('Unknown algorithm "%s"', $jwsAlgorithm));
        }

        $header['alg'] = $jwsAlgorithm;

        $payloadString = StringUtils::payload2string($payload, $context->jsonMapper());

        $signingInput = implode('.', [
            UrlSafeB64Encoder::encode(json_encode($header)),
            UrlSafeB64Encoder::encode($payloadString),
        ]);

        $signature = $hashAlgorithm->sign($signingInput, $key);
        $signature = UrlSafeB64Encoder::encode($signature);

        return $signingInput.'.'.$signature;
    }

    /**
     * @param Context         $context
     * @param string          $token
     * @param string|resource $key
     *
     * @return array
     */
    public static function decode(Context $context, $token, $key)
    {
        if (empty($token) || trim($token) === '') {
            throw new JoseJwtException('Incoming token expected to be in compact serialization form, but is empty');
        }

        $parts = explode('.', $token);
        if (count($parts) == 5) {
            return Jwe::decode($context, $token, $key);
        }

        $decodedParts = [];
        foreach ($parts as $part) {
            $decodedParts[] = UrlSafeB64Encoder::decode($part);
        }
        $header = json_decode($decodedParts[0], true);
        if (null == $header) {
            throw new JoseJwtException('Invalid header');
        }

        // signed or plain JWT
        $signedInput = $parts[0].'.'.$parts[1];
        $algorithmId = $header['alg'];
        $algorithm = $context->jwsAlgorithms()->get($algorithmId);
        if (null === $algorithm) {
            throw new JoseJwtException(sprintf('Invalid algorithm "%s"', $algorithmId));
        }

        if (false === $algorithm->verify($decodedParts[2], $signedInput, $key)) {
            throw new IntegrityException('Invalid signature');
        }

        return json_decode($decodedParts[1], true);
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
        if (count($parts) != 3 && count($parts) != 5) {
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
