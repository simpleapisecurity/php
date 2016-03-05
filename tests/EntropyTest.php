<?php

use SimpleAPISecurity\PHP\Entropy;
use SimpleAPISecurity\PHP\Constants;

class EntropyTest extends PHPUnit_Framework_TestCase
{
    /**
     * @requires extension libsodium
     */
    public function testBytes()
    {
        # Generate a random string of bytes.
        $randomString = Entropy::bytes();

        # Ensure the string is actually a string.
        $this->assertTrue((is_string($randomString)));

        # Ensure that the string is the correct length.
        $this->assertTrue((strlen($randomString) === Constants::BYTES));

        # Generate a new random string of bytes.
        $randomNewString = Entropy::bytes(Constants::BYTES + 32);

        # Ensure the string is actually a string.
        $this->assertTrue((is_string($randomNewString)));

        # Ensure that the string is the correct length.
        $this->assertTrue((strlen($randomNewString) === Constants::BYTES + 32));
    }

    /**
     * @depends testBytes
     * @expectedException SimpleAPISecurity\PHP\Exceptions\OutOfRangeException
     * @expectedExceptionMessageRegExp #Bytes range: \d+ to \d+#
     */
    public function testBytesExceptionTooHigh()
    {
        Entropy::bytes(Constants::BYTES_MAX + 32);
    }

    /**
     * @depends testBytes
     * @expectedException SimpleAPISecurity\PHP\Exceptions\OutOfRangeException
     * @expectedExceptionMessageRegExp #Bytes range: \d+ to \d+#
     */
    public function testBytesExceptionTooLow()
    {
        Entropy::bytes(Constants::BYTES_MIN - 1);
    }

    /**
     * @depends testBytes
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Expected integer parameter for bytes
     */
    public function testBytesInvalidType()
    {
        Entropy::bytes('testing');
    }

    /**
     * @requires extension libsodium
     */
    public function testRandomInteger()
    {
        # Get a random integer that should always be 1.
        $randomInteger = Entropy::integer(Constants::RANGE_MIN);

        # Ensure the string is actually an integer.
        $this->assertTrue((is_integer($randomInteger)));

        # Ensure that the string is the correct length.
        $this->assertTrue(($randomInteger === Constants::RANGE_MIN));
    }

    /**
     * @depends testRandomInteger
     * @expectedException SimpleAPISecurity\PHP\Exceptions\OutOfRangeException
     * @expectedExceptionMessageRegExp #Integer range: \d+ to \d+#
     */
    public function testRandomIntegerExceptionTooHigh()
    {
        Entropy::integer(Constants::RANGE_MAX + 1);
    }

    /**
     * @depends testRandomInteger
     * @expectedException SimpleAPISecurity\PHP\Exceptions\OutOfRangeException
     * @expectedExceptionMessageRegExp #Integer range: \d+ to \d+#
     */
    public function testRandomIntegerExceptionTooLow()
    {
        Entropy::integer(Constants::RANGE_MIN - 1);
    }

    /**
     * @depends testRandomInteger
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Expected integer parameter for integer
     */
    public function testRandomIntegerExceptionInvalidType()
    {
        Entropy::integer('test');
    }

    /**
     * @requires extension libsodium
     */
    public function test16BitInteger()
    {
        $this->assertTrue(is_integer(Entropy::integer16()));
    }
}