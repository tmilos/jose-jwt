<?php

namespace JoseJwt\Tests\Util;

use JoseJwt\Tests\Mock\PayloadJsonSerializable;
use JoseJwt\Util\StringUtils;

class StringUtilsPayloadToStringTest  extends \PHPUnit_Framework_TestCase
{
    public function test_json_encodes_array()
    {
        $payload = ['a'=>'a/a', 'b/b'=>2];
        $result = StringUtils::payload2string($payload);
        $this->assertEquals('{"a":"a/a","b/b":2}', $result);
    }

    public function test_returns_payload_string()
    {
        $payload = 'aaa';
        $this->assertEquals($payload, StringUtils::payload2string($payload));
    }

    public function empty_payload_provider()
    {
        return [
            [''],
            [null],
        ];
    }

    /**
     * @dataProvider empty_payload_provider
     *
     * @expectedException \JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Payload can not be empty
     */
    public function test_throws_on_empty_string_payload($payload)
    {
        StringUtils::payload2string($payload);
    }

    public function test_calls_json_serialize_on_objects_implementing_json_serializable()
    {
        $payload = new PayloadJsonSerializable('123');
        $result = StringUtils::payload2string($payload);
        $this->assertEquals('{"a":"123"}', $result);
    }

    public function test_calls_given_json_mapper()
    {
        $payload = new \stdClass();
        $jsonMapper = $this->getMock('JoseJwt\Json\JsonMapper');
        $jsonMapper->expects($this->once())->method('getJsonString')->with($payload)->willReturn($expectedResult = 'xxxx');

        $result = StringUtils::payload2string($payload, $jsonMapper);

        $this->assertEquals($expectedResult, $result);
    }

    /**
     * @expectedException \JoseJwt\Error\JoseJwtException
     * @expectedExceptionMessage Unable to serialize payload
     */
    public function test_throws_when_unable_to_serialize()
    {
        StringUtils::payload2string(new \stdClass());
    }
}
