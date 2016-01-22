<?php

namespace JoseJwt\Tests\Context;

use JoseJwt\Context\DefaultContext;

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
     * @return \PHPUnit_Framework_MockObject_MockObject|\JoseJwt\Json\JsonMapper
     */
    private function getJsonMapperMock()
    {
        return $this->getMock('JoseJwt\Json\JsonMapper');
    }
}
