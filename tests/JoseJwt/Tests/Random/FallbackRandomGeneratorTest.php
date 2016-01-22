<?php

namespace JoseJwt\Tests\Random;

use JoseJwt\Random\FallbackRandomGenerator;

class FallbackRandomGeneratorTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_wout_arguments()
    {
        new FallbackRandomGenerator();
    }

    public function test_constructs_with_one_random_generator()
    {
        new FallbackRandomGenerator($this->getRandomGeneratorMock());
    }

    public function test_constructs_with_two_random_generator()
    {
        new FallbackRandomGenerator($this->getRandomGeneratorMock(), $this->getRandomGeneratorMock());
    }

    public function test_constructs_with_null_and_random_generator()
    {
        new FallbackRandomGenerator(null, $this->getRandomGeneratorMock());
    }

    public function test_returns_first()
    {
        $generator = new FallbackRandomGenerator();
        $generator->setFirst($first = $this->getRandomGeneratorMock());
        $this->assertSame($first, $generator->getFirst());
    }

    public function test_returns_second()
    {
        $generator = new FallbackRandomGenerator();
        $generator->setSecond($second = $this->getRandomGeneratorMock());
        $this->assertSame($second, $generator->getSecond());
    }

    public function test_get_calls_first_if_set()
    {
        $expectedLength = 10;
        $generator = new FallbackRandomGenerator($first = $this->getRandomGeneratorMock(), $second = $this->getRandomGeneratorMock());
        $first->expects($this->once())->method('get')->with($expectedLength);
        $second->expects($this->never())->method('get');

        $generator->get($expectedLength);
    }

    public function test_get_calls_second_if_first_is_not_set()
    {
        $expectedLength = 10;
        $generator = new FallbackRandomGenerator(null, $second = $this->getRandomGeneratorMock());
        $second->expects($this->once())->method('get')->with($expectedLength);

        $generator->get($expectedLength);
    }

    /**
     * @expectedException \JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage No random generators provided
     */
    public function test_throws_if_none_is_set()
    {
        $generator = new FallbackRandomGenerator();
        $generator->get(10);
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|\JoseJwt\Random\RandomGenerator
     */
    private function getRandomGeneratorMock()
    {
        return $this->getMock('JoseJwt\Random\RandomGenerator');
    }
}
