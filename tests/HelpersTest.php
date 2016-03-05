<?php

use SimpleAPISecurity\PHP\Helpers;

class HelpersTest extends PHPUnit_Framework_TestCase
{
    private $ipv6 = 'fe80::a65e:60ff:fec0:6ee9';
    private $ipv6_converted = 'fe80a65e60fffec06ee9';
    private $mac = 'b6:f3:a8:30:2f:69';
    private $mac_converted = 'b6f3a8302f69';

    /**
     * @requires extension libsodium
     */
    public function testBinaryConversion()
    {
        $this->assertTrue((Helpers::bin2hex(Helpers::hex2bin('a1b2c3d4f5')) === 'a1b2c3d4f5'));
    }

    /**
     * @depends testBinaryConversion
     */
    public function testMacToBinary()
    {
        $testData = Helpers::macToBinary($this->mac);
        $this->assertTrue((Helpers::bin2hex($testData) === $this->mac_converted));
    }

    /**
     * @depends testBinaryConversion
     */
    public function testIPv6ToBinary()
    {
        $testData = Helpers::ipv6ToBinary($this->ipv6);
        $this->assertTrue((Helpers::bin2hex($testData) === $this->ipv6_converted));
    }

    /**
     * @requires extension libsodium
     */
    public function testStringCompare()
    {
        $this->assertTrue((Helpers::stringCompare('test', 'test')));
        $this->assertFalse((Helpers::stringCompare('test', 'nottest')));
    }
}