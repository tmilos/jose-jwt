# jose-jwt
Javascript Object Signing and Encryption JOSE PHP library, supporting JSON Web Tokens JWT and JSON Web Encryption JWE.

[![Author](http://img.shields.io/badge/author-@tmilos-blue.svg?style=flat-square)](https://twitter.com/tmilos77)
[![License](https://img.shields.io/packagist/l/tmilos/jose-jwt.svg)](https://packagist.org/packages/tmilos/jose-jwt)
[![Build Status](https://travis-ci.org/tmilos/jose-jwt.svg?branch=master)](https://travis-ci.org/tmilos/jose-jwt)
[![Coverage Status](https://coveralls.io/repos/tmilos/jose-jwt/badge.svg?branch=master&service=github)](https://coveralls.io/github/tmilos/jose-jwt?branch=master)
[![HHVM Status](http://hhvm.h4cc.de/badge/tmilos/jose-jwt.svg)](http://hhvm.h4cc.de/package/tmilos/jose-jwt)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/tmilos/jose-jwt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/tmilos/jose-jwt/?branch=master)

## JWT algorithms

Supported signing algorithms

| JWS Algorithm    |
| ---------------- |
| none             |
| HS256            |
| HS384            |
| HS512            |
| RS256            |
| RS384            |
| RS512            |


## JWE algorithms and encryptions

Supported JWE algorithms

| JWE Algorithm    |
| ---------------- |
| RSA1_5           |
| RSA-OAEP         |
| A128KW           |
| A192KW           |
| A256KW           |
| dir              |


Supported JWE encryption

| JWE Encryption   |
| ---------------- |
| A128CBC-HS256    |
| A192CBC-HS384    |
| A256CBC-HS512    |


## JWT API

```php
$factory = new \Tmilos\JoseJwt\Context\DefaultContextFactory();
$context = $factory->get();

$payload = ['msg' => 'Hello!'];
$extraHeader = ['iam'=>'my-id'];

// plain (no signature) token
$token = \Tmilos\JoseJwt\Jwt::encode($context, $payload, null, \Tmilos\JoseJwt\Jws\JwsAlgorithm::NONE, $extraHeader);

// HS256 signature
$secret = '...'; // 256 bits secret
$token = \Tmilos\JoseJwt\Jwt::encode($context, $payload, $secret, \Tmilos\JoseJwt\Jws\JwsAlgorithm::HS256, $extraHeader);

// HS384 signature
$secret = '...'; // 256 bits secret
$token = \Tmilos\JoseJwt\Jwt::encode($context, $payload, $secret, \Tmilos\JoseJwt\Jws\JwsAlgorithm::HS384, $extraHeader);

// HS512 signature
$secret = '...'; // 256 bits secret
$token = \Tmilos\JoseJwt\Jwt::encode($context, $payload, $secret, \Tmilos\JoseJwt\Jws\JwsAlgorithm::HS512, $extraHeader);

// RS256
$privateKey = openssl_get_privatekey($filename);
$token = \Tmilos\JoseJwt\Jwt::encode($context, $payload, $secret, \Tmilos\JoseJwt\Jws\JwsAlgorithm::RS256, $extraHeader);

// RS384
$privateKey = openssl_get_privatekey($filename);
$token = \Tmilos\JoseJwt\Jwt::encode($context, $payload, $secret, \Tmilos\JoseJwt\Jws\JwsAlgorithm::RS384, $extraHeader);

// RS512
$privateKey = openssl_get_privatekey($filename);
$token = \Tmilos\JoseJwt\Jwt::encode($context, $payload, $secret, \Tmilos\JoseJwt\Jws\JwsAlgorithm::RS512, $extraHeader);

// decode
$header = \Tmilos\JoseJwt\Jwt::header($token);
// eventually also use other header data to indicate which key should be used
switch($header['alg']) {
    case \Tmilos\JoseJwt\Jws\JwsAlgorithm::NONE:
        $key = null;
        break;
    case \Tmilos\JoseJwt\Jws\JwsAlgorithm::HS256:
    case \Tmilos\JoseJwt\Jws\JwsAlgorithm::HS384:
    case \Tmilos\JoseJwt\Jws\JwsAlgorithm::HS512:
        $key = $secret;
        break;
    case \Tmilos\JoseJwt\Jws\JwsAlgorithm::RS256:
    case \Tmilos\JoseJwt\Jws\JwsAlgorithm::RS384:
    case \Tmilos\JoseJwt\Jws\JwsAlgorithm::RS512:
        $key = $publicKey;
        break;
}
$payload = \Tmilos\JoseJwt\JWT::decode($context, $token, $key);
```

## JWE API

```php
$factory = new \Tmilos\JoseJwt\Context\DefaultContextFactory();
$context = $factory->get();

// Symmetric
$payload = ['msg' => 'Hello!'];
$extraHeader = ['iam'=>'my-id'];

// DIR - A128CBC-HS256
$secret = '...'; // 256 bits secret
$token = \Tmilos\JoseJwt\Jwe::encode($context, $payload, $secret, \Tmilos\JoseJwt\Jwe\JweAlgorithm::DIR, \Tmilos\JoseJwt\Jwe\JweEncryption::A128CBC_HS256, $extraHeaders);

// DIR - A192CBC-HS384
$secret = '...'; // 384 bits secret
$token = \Tmilos\JoseJwt\Jwe::encode($context, $payload, $secret, \Tmilos\JoseJwt\Jwe\JweAlgorithm::DIR, \Tmilos\JoseJwt\Jwe\JweEncryption::A192CBC_HS384, $extraHeaders);

// DIR - A256CBC-HS512
$secret = '...'; // 512 bits secret
$token = \Tmilos\JoseJwt\Jwe::encode($context, $payload, $secret, \Tmilos\JoseJwt\Jwe\JweAlgorithm::DIR, \Tmilos\JoseJwt\Jwe\JweEncryption::A256CBC_HS512, $extraHeaders);

// decode
$payload = \Tmilos\JoseJwt\Jwe::decode($context, $token, $secret);

// RSA
$myPrivateKey = openssl_get_privatekey();
$partyPublicKey = openssl_get_publickey();

// RSA_OAEP - A128CBC-HS256
$token = \Tmilos\JoseJwt\Jwe::encode($context, $payload, $partyPublicKey, \Tmilos\JoseJwt\Jwe\JweAlgorithm::RSA_OAEP, \Tmilos\JoseJwt\Jwe\JweEncryption::A128CBC_HS256, $extraHeaders);

// RSA_OAEP - A256CBC-HS512
$token = \Tmilos\JoseJwt\Jwe::encode($context, $payload, $partyPublicKey, \Tmilos\JoseJwt\Jwe\JweAlgorithm::RSA_OAEP, \Tmilos\JoseJwt\Jwe\JweEncryption::A256CBC_HS512, $extraHeaders);

// decode
$payload = \Tmilos\JoseJwt\Jwe::decode($context, $token, $myPrivateKey);

// read header w/out decryption
$header = \Tmilos\Tmilos\JoseJwt\Jwe::decode($token); // {"alg": "A192KW", "enc": "A128CBC-HS256", "typ": "JWT", "custom": "X"}
```
