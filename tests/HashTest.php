<?php

use SimpleAPISecurity\PHP\Constants;
use SimpleAPISecurity\PHP\Hash;

class HashTest extends PHPUnit_Framework_TestCase
{
    /**
     * @requires extension libsodium
     */
    public function testGenericHash()
    {
        $this->assertTrue((strlen(Hash::hash('test')) === Constants::GENERICHASH_BYTES));
    }

    /**
     * @depends testGenericHash
     */
    public function testHashKeys()
    {
        $key = Hash::generateKey();

        $msg1 = Hash::hash('test', $key);
        $msg2 = Hash::hash('test', $key);

        $this->assertTrue(($msg1 === $msg2));
    }

    /**
     * @depends testGenericHash
     */
    public function testKeyLength()
    {
        $this->assertTrue((strlen(Hash::generateKey(Constants::GENERICHASH_KEYBYTES)) === Constants::GENERICHASH_KEYBYTES));
        $this->assertTrue((strlen(Hash::generateKey(Constants::GENERICHASH_KEYBYTES_MIN)) === Constants::GENERICHASH_KEYBYTES_MIN));
        $this->assertTrue((strlen(Hash::generateKey(Constants::GENERICHASH_KEYBYTES_MAX)) === Constants::GENERICHASH_KEYBYTES_MAX));
    }

    /**
     * @depends testGenericHash
     */
    public function testHashLength()
    {
        $this->assertTrue((strlen(Hash::hash('test', '', Constants::GENERICHASH_BYTES_MAX)) === Constants::GENERICHASH_BYTES_MAX));
        $this->assertTrue((strlen(Hash::hash('test', '', Constants::GENERICHASH_BYTES_MIN)) === Constants::GENERICHASH_BYTES_MIN));
    }

    /**
     * @requires extension libsodium
     * @depends testGenericHash
     */
    public function testShortHash()
    {
        $key = Hash::generateKey(Constants::GENERICHASH_KEYBYTES_MIN);
        $this->assertTrue((strlen($key) === Constants::GENERICHASH_KEYBYTES_MIN));
        $this->assertTrue((strlen(Hash::shortHash('test', $key)) === 8));
    }
}