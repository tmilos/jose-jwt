<?php

namespace JoseJwt;

use JoseJwt\Error\JoseJwtException;
use JoseJwt\Util\StringUtils;
use JoseJwt\Util\UrlSafeB64Encoder;

class Jwe
{
    private function __construct()
    {
    }

    public static function encode(Configuration $configuration, $payload, $key, $jweAlgorithm, $jweEncryption, array $extraHeaders = [])
    {
        if (empty($payload) || (is_string($payload) && trim($payload) == '')) {
            throw new JoseJwtException('Payload can not be empty');
        }
        $algorithm = $configuration->getJweAlgorithm($jweAlgorithm);
        if (null === $algorithm) {
            throw new JoseJwtException(sprintf('Invalid or unsupported algorithm "%s"', $jweAlgorithm));
        }
        $encryption = $configuration->getJweEncryption($jweEncryption);
        if (null === $encryption) {
            throw new JoseJwtException(sprintf('Invalid or unsupported encryption "%s"', $jweEncryption));
        }

        $header = array_merge([
            'alg' => $jweAlgorithm,
            'enc' => $jweEncryption,
            'typ' => 'JWT',
        ], $extraHeaders);

        list($cek, $encryptedCek) = $algorithm->wrapNewKey($encryption->getKeySize(), $key, $header);

        $payloadString = StringUtils::payload2string($payload, $configuration->getJsonMapper());

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
     * @param Configuration   $configuration
     * @param string          $token
     * @param string|resource $key
     *
     * @return string
     */
    public static function decode(Configuration $configuration, $token, $key)
    {
        if (empty($token) || trim($token) === '') {
            throw new JoseJwtException('Incoming token expected to be in compact serialization form, but is empty');
        }

        $parts = explode('.', $token);
        if (count($parts) != 5) {
            throw new JoseJwtException('Invalid JWE token');
        }

        $decodedParts = [];
        foreach ($parts as $part) {
            $decodedParts[] = UrlSafeB64Encoder::decode($part);
        }

        $headerString = $decodedParts[0];
        $encryptedCek = $decodedParts[1];
        $iv = $decodedParts[2];
        $cipherText = $decodedParts[3];
        $authTag = $decodedParts[4];

        $header = json_decode($headerString, true);

        $algorithm = $configuration->getJweAlgorithm($header['alg']);
        $encryption = $configuration->getJweEncryption($header['enc']);

        $cek = $algorithm->unwrap($encryptedCek, $key, $encryption->getKeySize(), $header);
        $aad = $parts[0];

        $plainText = $encryption->decrypt($aad, $cek, $iv, $cipherText, $authTag);

        return $plainText;
    }
}
