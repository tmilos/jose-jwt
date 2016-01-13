<?php

namespace JoseJwt\Json;

interface JsonMapper
{
    /**
     * @param $object
     *
     * @return string
     */
    public function getJsonString($object);

    /**
     * @param array $data
     *
     * @return void
     */
    public static function parseFromJsonData(array $data);
}
