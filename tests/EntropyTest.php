<?php

use SimpleAPISecurity\PHP\Entropy;
use SimpleAPISecurity\PHP\Helpers;
use SimpleAPISecurity\PHP\Constants;

class EntropyTest extends PHPUnit_Framework_TestCase
{
    private $nonceData = [
        'old' => 'e9373bdbb866f485484a9c499c1e36eeeb8c6d2a734f5ae1',
        'new' => 'ea373bdbb866f485484a9c499c1e36eeeb8c6d2a734f5ae1',
    ];

    /**
     * @requires extension libsodium
     */
    public function testNonceSize()
    {
        $this->assertTrue((strlen(Entropy::generateNonce()) === 24));
    }

    /**
     * @depends testNonceSize
     */
    public function testNonceProgressed()
    {
        $this->assertTrue((Helpers::nonceCheck(
                Helpers::hex2bin($this->nonceData['old']),
                Helpers::hex2bin($this->nonceData['new'])
            ) === 'MSG_PROGRESSED'));
    }

    /**
     * @depends testNonceSize
     */
    public function testNonceSame()
    {
        $this->assertTrue((Helpers::nonceCheck(
                Helpers::hex2bin($this->nonceData['old']),
                Helpers::hex2bin($this->nonceData['old'])
            ) === 'MSG_SAME'));
    }

    /**
     * @depends testNonceSize
     */
    public function testNonceFastForward()
    {
        $this->assertTrue((Helpers::nonceCheck(
                Helpers::hex2bin($this->nonceData['new']),
                Helpers::hex2bin($this->nonceData['old'])
            ) === 'MSG_FAST_FORWARD'));
    }

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
     * @expectedExceptionMessageRegExp #Integer range for bytes in Entropy is \d+ to \d+#
     */
    public function testBytesExceptionTooHigh()
    {
        Entropy::bytes(Constants::BYTES_MAX + 32);
    }

    /**
     * @depends testBytes
     * @expectedException SimpleAPISecurity\PHP\Exceptions\OutOfRangeException
     * @expectedExceptionMessageRegExp #Integer range for bytes in Entropy is \d+ to \d+#
     */
    public function testBytesExceptionTooLow()
    {
        Entropy::bytes(Constants::BYTES_MIN - 1);
    }

    /**
     * @depends testBytes
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Integer parameter expected for bytes in Entropy
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
     * @expectedExceptionMessageRegExp #Integer range for integer in Entropy is \d+ to \d+#
     */
    public function testRandomIntegerExceptionTooHigh()
    {
        Entropy::integer(Constants::RANGE_MAX + 1);
    }

    /**
     * @depends testRandomInteger
     * @expectedException SimpleAPISecurity\PHP\Exceptions\OutOfRangeException
     * @expectedExceptionMessageRegExp #Integer range for integer in Entropy is \d+ to \d+#
     */
    public function testRandomIntegerExceptionTooLow()
    {
        Entropy::integer(Constants::RANGE_MIN - 1);
    }

    /**
     * @depends testRandomInteger
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Integer parameter expected for integer in Entropy
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