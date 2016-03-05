<?php

namespace SimpleAPISecurity\PHP\Exceptions;


class ExceptionTemplate extends \Exception
{
    public function __toString() {
        return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
    }
}