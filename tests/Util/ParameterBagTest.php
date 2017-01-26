<?php

namespace Tests\Tmilos\JoseJwt\Util;

use Tmilos\JoseJwt\Util\ParameterBag;

class ParameterBagTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_wout_arguments()
    {
        new ParameterBag();
    }

    public function test_constructs_with_parameters_array()
    {
        new ParameterBag(['a'=>1, 'b'=>2]);
    }

    public function test_all()
    {
        $bag = new ParameterBag($expected = ['a'=>1, 'b'=>2]);
        $this->assertEquals($expected, $bag->all());
    }

    public function test_keys()
    {
        $bag = new ParameterBag(['a'=>1, 'b'=>2]);
        $this->assertEquals(['a', 'b'], $bag->keys());
    }

    public function test_add()
    {
        $bag = new ParameterBag(['a'=>1, 'b'=>2]);
        $bag->add(['b'=>3, 'c'=>4]);
        $this->assertEquals(['a'=>1, 'b'=>3, 'c'=>4], $bag->all());
    }

    public function test_remove()
    {
        $bag = new ParameterBag(['a'=>1, 'b'=>2]);
        $bag->remove('a');
        $this->assertEquals(['b'=>2], $bag->all());
    }

    public function test_count()
    {
        $bag = new ParameterBag(['a'=>1, 'b'=>2]);
        $this->assertEquals(2, $bag->count());
    }

    public function test_iterator()
    {
        $bag = new ParameterBag($expected = ['a'=>1, 'b'=>2]);
        foreach ($bag as $k=>$v) {
            $this->assertTrue(array_key_exists($k, $expected));
            $this->assertEquals($expected[$k], $v);
            unset($expected[$k]);
        }
        $this->assertEmpty($expected);
    }
}
