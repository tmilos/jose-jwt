<?php

/*
 * This file is part of the tmilos/jose-jwt package.
 *
 * (c) Milos Tomic <tmilos@gmail.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace Tmilos\JoseJwt\Json;

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
