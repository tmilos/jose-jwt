<?php

namespace JoseJwt\Tests;

use JoseJwt\Jwe;

class JweTest extends AbstractTestBase
{
    public function symmetric_provider()
    {
        return [
            ['DIR - A128CBC-HS256', 256, Jwe\JweAlgorithm::DIR, Jwe\JweEncryption::A128CBC_HS256, $this->randoms['DIR - A128CBC-HS256']],
            ['DIR - A192CBC-HS384', 384, Jwe\JweAlgorithm::DIR, Jwe\JweEncryption::A192CBC_HS384, $this->randoms['DIR - A192CBC-HS384']],
            ['DIR - A256CBC-HS512', 512, Jwe\JweAlgorithm::DIR, Jwe\JweEncryption::A256CBC_HS512, $this->randoms['DIR - A256CBC-HS512']],

            ['A128KW - A128CBC-HS256', 128, Jwe\JweAlgorithm::A128KW, Jwe\JweEncryption::A128CBC_HS256, $this->randoms['A128KW - A128CBC-HS256']],
            ['A128KW - A128CBC-HS384', 128, Jwe\JweAlgorithm::A128KW, Jwe\JweEncryption::A192CBC_HS384, $this->randoms['A128KW - A128CBC-HS384']],
            ['A128KW - A256CBC-HS512', 128, Jwe\JweAlgorithm::A128KW, Jwe\JweEncryption::A256CBC_HS512, $this->randoms['A128KW - A256CBC-HS512']],

            ['A192KW - A128CBC-HS256', 192, Jwe\JweAlgorithm::A192KW, Jwe\JweEncryption::A128CBC_HS256, $this->randoms['A192KW - A128CBC-HS256']],
            ['A192KW - A128CBC-HS384', 192, Jwe\JweAlgorithm::A192KW, Jwe\JweEncryption::A192CBC_HS384, $this->randoms['A192KW - A128CBC-HS384']],
            ['A192KW - A256CBC-HS512', 192, Jwe\JweAlgorithm::A192KW, Jwe\JweEncryption::A256CBC_HS512, $this->randoms['A192KW - A256CBC-HS512']],

            ['A256KW - A128CBC-HS256', 256, Jwe\JweAlgorithm::A256KW, Jwe\JweEncryption::A128CBC_HS256, $this->randoms['A256KW - A128CBC-HS256']],
            ['A256KW - A128CBC-HS384', 256, Jwe\JweAlgorithm::A256KW, Jwe\JweEncryption::A192CBC_HS384, $this->randoms['A256KW - A128CBC-HS384']],
            ['A256KW - A256CBC-HS512', 256, Jwe\JweAlgorithm::A256KW, Jwe\JweEncryption::A256CBC_HS512, $this->randoms['A256KW - A256CBC-HS512']],
        ];
    }

    /**
     * @dataProvider symmetric_provider
     */
    public function test_symmetric($tokenName, $secretSize, $algorithm, $encryption, array $randomSequences)
    {
        foreach ($randomSequences as $randomSequence) {
            $this->addRandomSequence($randomSequence);
        }
        $token = Jwe::encode($this->context, $this->payload, $key = $this->getSecret($secretSize), $algorithm, $encryption, $this->extraHeader);
        $this->assertEquals($this->tokens[$tokenName], $token);

        $decrypted = Jwe::decode($this->context, $token, $key);
        $payload = json_decode($decrypted, true);
        $this->assertEquals($this->payload, $payload);
    }

    public function rsa_provider()
    {
        return [
            [Jwe\JweAlgorithm::RSA1_5, Jwe\JweEncryption::A128CBC_HS256],
            [Jwe\JweAlgorithm::RSA1_5, Jwe\JweEncryption::A192CBC_HS384],
            [Jwe\JweAlgorithm::RSA1_5, Jwe\JweEncryption::A256CBC_HS512],
            [Jwe\JweAlgorithm::RSA_OAEP, Jwe\JweEncryption::A128CBC_HS256],
            [Jwe\JweAlgorithm::RSA_OAEP, Jwe\JweEncryption::A192CBC_HS384],
            [Jwe\JweAlgorithm::RSA_OAEP, Jwe\JweEncryption::A256CBC_HS512],
        ];
    }

    /**
     * @dataProvider rsa_provider
     */
    public function test_rsa_crypt_decrypt($algorithm, $encryption)
    {
        $token = Jwe::encode($this->context, $this->payload, $this->getRsaPublicKey(), $algorithm, $encryption, $this->extraHeader);
        $payload = Jwe::decode($this->context, $token, $this->getRsaPrivateKey());
        $payload = json_decode($payload, true);
        $this->assertEquals($this->payload, $payload);
    }

    public function rsa_decrypt_provider()
    {
        return [
            ['RSA_OAEP - A128CBC-HS256'],
            ['RSA_OAEP - A256CBC-HS512'],
            ['RSA1_5 - A128CBC-HS256'],
            ['RSA1_5 - A256CBC-HS512'],
        ];
    }

    /**
     * @dataProvider rsa_decrypt_provider
     */
    public function test_rsa_decrypt($tokenName)
    {
        $payload = Jwe::decode($this->context, $this->tokens[$tokenName], $this->getRsaPrivateKey());
        $payload = json_decode($payload, true);
        $this->assertEquals($this->payload, $payload);
    }
}
