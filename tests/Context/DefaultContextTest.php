<?php

namespace Tests\Tmilos\JoseJwt\Context;

use Tmilos\JoseJwt\Context\DefaultContext;
use Tmilos\JoseJwt\Json\JsonMapper;

class DefaultContextTest extends \PHPUnit_Framework_TestCase
{
    public function test_constructs_wout_arguments()
    {
        new DefaultContext();
    }

    public function test_json_mapper_get_set()
    {
        $context = new DefaultContext();
        $context->setJsonMapper($expected = $this->getJsonMapperMock());
        $this->assertSame($expected, $context->jsonMapper());
    }

    /**
     * @return \PHPUnit_Framework_MockObject_MockObject|JsonMapper
     */
    private function getJsonMapperMock()
    {
        return $this->getMockBuilder(JsonMapper::class)->getMock();
    }
}
