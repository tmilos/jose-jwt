<?php

namespace JoseJwt\Context;

interface ContextFactory
{
    /**
     * @return Context
     */
    public function get();
}
