<?php

namespace JoseJwt\Tests\Context;

use JoseJwt\Context\DefaultContextFactory;
use JoseJwt\Jwe\JweAlgorithm;
use JoseJwt\Jwe\JweEncryption;
use JoseJwt\Jws\JwsAlgorithm;

class DefaultContextFactoryTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_wout_arguments()
    {
        new DefaultContextFactory();
    }

    public function test_constructs_with_random_generator()
    {
        new DefaultContextFactory($this->getRandomGeneratorMock());
    }

    public function test_can_set_random_generator()
    {
        $factory = new DefaultContextFactory();
        $factory->setRandomGenerator($this->getRandomGeneratorMock());
    }

    public function jws_algorithm_provider()
    {
        return [
            [JwsAlgorithm::NONE],
            [JwsAlgorithm::HS256],
            [JwsAlgorithm::HS384],
            [JwsAlgorithm::HS512],
            [JwsAlgorithm::RS256],
            [JwsAlgorithm::RS384],
            [JwsAlgorithm::RS512],
        ];
    }

    /**
     * @dataProvider jws_algorithm_provider
     */
    public function test_provides_jws_algorithm($id)
    {
        $factory = new DefaultContextFactory();
        $context = $factory->get();
        $this->assertTrue($context->jwsAlgorithms()->has($id));
        $this->assertInstanceOf('JoseJwt\Jws\JwsAlgorithm', $context->jwsAlgorithms()->get($id));
    }

    public function jwe_algorithm_provider()
    {
        return [
            [JweAlgorithm::DIR],
            [JweAlgorithm::RSA1_5],
            [JweAlgorithm::RSA_OAEP],
            [JweAlgorithm::A128KW],
            [JweAlgorithm::A192KW],
            [JweAlgorithm::A256KW],
        ];
    }

    /**
     * @dataProvider jwe_algorithm_provider
     */
    public function test_provides_jwe_algorithm($id)
    {
        $factory = new DefaultContextFactory();
        $context = $factory->get();
        $this->assertTrue($context->jweAlgorithms()->has($id));
        $this->assertInstanceOf('JoseJwt\Jwe\JweAlgorithm', $context->jweAlgorithms()->get($id));
    }

    public function jwe_encryption_provider()
    {
        return [
            [JweEncryption::A128CBC_HS256],
            [JweEncryption::A192CBC_HS384],
            [JweEncryption::A256CBC_HS512],
        ];
    }

    /**
     * @dataProvider jwe_encryption_provider
     */
    public function test_provides_jwe_encryption($id)
    {
        $factory = new DefaultContextFactory();
        $context = $factory->get();
        $this->assertTrue($context->jweEncryptions()->has($id));
        $this->assertInstanceOf('JoseJwt\Jwe\JweEncryption', $context->jweEncryptions()->get($id));
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\JoseJwt\Random\RandomGenerator
     */
    private function getRandomGeneratorMock()
    {
        return $this->getMock('JoseJwt\Random\RandomGenerator');
    }
}
