<?php

namespace Tests\Tmilos\JoseJwt\Jwe;

use Tmilos\JoseJwt\Jwe\JweEncryption;
use Tmilos\JoseJwt\Jwe\JweEncryptionCollection;

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
        $encryption = $this->getMockBuilder(JweEncryption::class)->getMock();
        $collection = new JweEncryptionCollection();
        $this->assertFalse($collection->has($id));
        $collection->add($id, $encryption);
        $this->assertTrue($collection->has($id));
        $this->assertSame($encryption, $collection->get($id));
        $this->assertEquals([$id => $encryption], $collection->all());
    }
}
