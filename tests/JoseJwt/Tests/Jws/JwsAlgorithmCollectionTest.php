<?php

namespace JoseJwt\Tests\Jws;

use JoseJwt\Jws\JwsAlgorithm;
use JoseJwt\Jws\JwsAlgorithmCollection;

class JwsAlgorithmCollectionTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_wout_arguments()
    {
        new JwsAlgorithmCollection();
    }

    public function test_whole_class()
    {
        $id = 'foo';
        /** @var JwsAlgorithm $algorithm */
        $algorithm = $this->getMock('JoseJwt\Jws\JwsAlgorithm');
        $collection = new JwsAlgorithmCollection();
        $this->assertFalse($collection->has($id));
        $collection->add($id, $algorithm);
        $this->assertTrue($collection->has($id));
        $this->assertSame($algorithm, $collection->get($id));
        $this->assertEquals([$id => $algorithm], $collection->all());
    }
}
