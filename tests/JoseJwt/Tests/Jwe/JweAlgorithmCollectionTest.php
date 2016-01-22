<?php

namespace JoseJwt\Tests\Jwe;

use JoseJwt\Jwe\JweAlgorithm;
use JoseJwt\Jwe\JweAlgorithmCollection;

class JweAlgorithmCollectionTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_wout_arguments()
    {
        new JweAlgorithmCollection();
    }

    public function test_whole_class()
    {
        $id = 'foo';
        /** @var JweAlgorithm $algorithm */
        $algorithm = $this->getMock('JoseJwt\Jwe\JweAlgorithm');
        $collection = new JweAlgorithmCollection();
        $this->assertFalse($collection->has($id));
        $collection->add($id, $algorithm);
        $this->assertTrue($collection->has($id));
        $this->assertSame($algorithm, $collection->get($id));
        $this->assertEquals([$id => $algorithm], $collection->all());
    }
}
