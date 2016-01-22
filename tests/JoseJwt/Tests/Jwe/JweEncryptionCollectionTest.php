<?php

namespace JoseJwt\Tests\Jwe;

use JoseJwt\Jwe\JweEncryption;
use JoseJwt\Jwe\JweEncryptionCollection;

class JweEncryptionCollectionTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_wout_arguments()
    {
        new JweEncryptionCollection();
    }

    public function test_whole_class()
    {
        $id = 'foo';
        /** @var JweEncryption $encryption */
        $encryption = $this->getMock('JoseJwt\Jwe\JweEncryption');
        $collection = new JweEncryptionCollection();
        $this->assertFalse($collection->has($id));
        $collection->add($id, $encryption);
        $this->assertTrue($collection->has($id));
        $this->assertSame($encryption, $collection->get($id));
        $this->assertEquals([$id => $encryption], $collection->all());
    }
}
