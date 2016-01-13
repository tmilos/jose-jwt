<?php

namespace JoseJwt;

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

        return $registry;
    }
}
