<?php

namespace JoseJwt;

use JoseJwt\Jwe\AesCbcHmacEncryption;
use JoseJwt\Jwe\AesKeyWrapAlgorithm;
use JoseJwt\Jwe\DirectAlgorithm;
use JoseJwt\Jwe\JweAlgorithm;
use JoseJwt\Jwe\JweEncryption;
use JoseJwt\Jwe\RsaAlgorithm;
use JoseJwt\Jws\HmacUsingSha;
use JoseJwt\Jws\JwsAlgorithm;
use JoseJwt\Jws\PlainText;
use JoseJwt\Jws\RsaUsingSha;

class Factory
{
    /**
     * @return Configuration
     */
    public function getConfiguration()
    {
        $registry = new Configuration();
        $registry
            ->addHashAlgorithm(JwsAlgorithm::NONE, new PlainText())
            ->addHashAlgorithm(JwsAlgorithm::HS256, new HmacUsingSha('sha256'))
            ->addHashAlgorithm(JwsAlgorithm::HS384, new HmacUsingSha('sha384'))
            ->addHashAlgorithm(JwsAlgorithm::HS512, new HmacUsingSha('sha512'))
            ->addHashAlgorithm(JwsAlgorithm::RS256, new RsaUsingSha('sha256'))
            ->addHashAlgorithm(JwsAlgorithm::RS384, new RsaUsingSha('sha384'))
            ->addHashAlgorithm(JwsAlgorithm::RS512, new RsaUsingSha('sha512'))
        ;

        $registry
            ->addJweAlgorithm(JweAlgorithm::RSA1_5, new RsaAlgorithm(OPENSSL_PKCS1_PADDING))
            ->addJweAlgorithm(JweAlgorithm::RSA_OAEP, new RsaAlgorithm(OPENSSL_PKCS1_OAEP_PADDING))
            ->addJweAlgorithm(JweAlgorithm::A128KW, new AesKeyWrapAlgorithm(128))
            ->addJweAlgorithm(JweAlgorithm::A192KW, new AesKeyWrapAlgorithm(192))
            ->addJweAlgorithm(JweAlgorithm::A256KW, new AesKeyWrapAlgorithm(256))
            ->addJweAlgorithm(JweAlgorithm::DIR, new DirectAlgorithm())
        ;

        $registry
            ->addJweEncryption(JweEncryption::A128CBC_HS256, new AesCbcHmacEncryption(256, new HmacUsingSha('sha256')))
            ->addJweEncryption(JweEncryption::A192CBC_HS384, new AesCbcHmacEncryption(384, new HmacUsingSha('sha384')))
            ->addJweEncryption(JweEncryption::A256CBC_HS512, new AesCbcHmacEncryption(512, new HmacUsingSha('sha512')))
        ;

        return $registry;
    }
}
