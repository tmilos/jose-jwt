<?php

namespace JoseJwt\Context;

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
use JoseJwt\Random\OpenSslRandomGenerator;
use JoseJwt\Random\RandomGenerator;

class DefaultContextFactory implements ContextFactory
{
    /** @var RandomGenerator */
    private $randomGenerator;

    /**
     * @param RandomGenerator $randomGenerator
     */
    public function __construct(RandomGenerator $randomGenerator = null)
    {
        $this->randomGenerator = $randomGenerator;
    }

    /**
     * @param RandomGenerator $randomGenerator
     *
     * @return DefaultContextFactory
     */
    public function setRandomGenerator(RandomGenerator $randomGenerator = null)
    {
        $this->randomGenerator = $randomGenerator;

        return $this;
    }

    /**
     * @return Context
     */
    public function get()
    {
        $randomGenerator = $this->randomGenerator ?: new OpenSslRandomGenerator();

        $context = new DefaultContext($randomGenerator);

        $context->jwsAlgorithms()
            ->add(JwsAlgorithm::NONE, new PlainText())
            ->add(JwsAlgorithm::HS256, new HmacUsingSha('sha256'))
            ->add(JwsAlgorithm::HS384, new HmacUsingSha('sha384'))
            ->add(JwsAlgorithm::HS512, new HmacUsingSha('sha512'))
            ->add(JwsAlgorithm::RS256, new RsaUsingSha('sha256'))
            ->add(JwsAlgorithm::RS384, new RsaUsingSha('sha384'))
            ->add(JwsAlgorithm::RS512, new RsaUsingSha('sha512'))
        ;

        $context->jweAlgorithms()
            ->add(JweAlgorithm::RSA1_5, new RsaAlgorithm(OPENSSL_PKCS1_PADDING, $randomGenerator))
            ->add(JweAlgorithm::RSA_OAEP, new RsaAlgorithm(OPENSSL_PKCS1_OAEP_PADDING, $randomGenerator))
            ->add(JweAlgorithm::A128KW, new AesKeyWrapAlgorithm(128, $randomGenerator))
            ->add(JweAlgorithm::A192KW, new AesKeyWrapAlgorithm(192, $randomGenerator))
            ->add(JweAlgorithm::A256KW, new AesKeyWrapAlgorithm(256, $randomGenerator))
            ->add(JweAlgorithm::DIR, new DirectAlgorithm())
        ;

        $context->jweEncryptions()
            ->add(JweEncryption::A128CBC_HS256, new AesCbcHmacEncryption(256, new HmacUsingSha('sha256'), $randomGenerator))
            ->add(JweEncryption::A192CBC_HS384, new AesCbcHmacEncryption(384, new HmacUsingSha('sha384'), $randomGenerator))
            ->add(JweEncryption::A256CBC_HS512, new AesCbcHmacEncryption(512, new HmacUsingSha('sha512'), $randomGenerator))
        ;

        return $context;
    }
}
