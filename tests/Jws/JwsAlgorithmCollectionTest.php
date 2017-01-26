<?php

namespace Tests\Tmilos\JoseJwt\Jws;

use Tmilos\JoseJwt\Jws\JwsAlgorithm;
use Tmilos\JoseJwt\Jws\JwsAlgorithmCollection;

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
        $algorithm = $this->getMockBuilder(JwsAlgorithm::class)->getMock();
        $collection = new JwsAlgorithmCollection();
        $this->assertFalse($collection->has($id));
        $collection->add($id, $algorithm);
        $this->assertTrue($collection->has($id));
        $this->assertSame($algorithm, $collection->get($id));
        $this->assertEquals([$id => $algorithm], $collection->all());
    }
}
