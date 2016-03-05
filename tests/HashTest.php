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
     * @expectedException SimpleAPISecurity\PHP\Exceptions\OutOfRangeException
     * @expectedExceptionMessageRegExp #generateKey length range: \d+ to \d+#
     */
    public function testGenerateKeyExceptionHigh()
    {
        Hash::generateKey(Constants::GENERICHASH_KEYBYTES_MAX + 1);
    }

    /**
     * @depends testGenericHash
     * @expectedException SimpleAPISecurity\PHP\Exceptions\OutOfRangeException
     * @expectedExceptionMessageRegExp #generateKey length range: \d+ to \d+#
     */
    public function testGenerateKeyExceptionLow()
    {
        Hash::generateKey(Constants::GENERICHASH_KEYBYTES_MIN - 1);
    }

    /**
     * @depends testGenericHash
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Expected integer parameter for generateKey
     */
    public function testGenerateKeyExceptionBadValue()
    {
        Hash::generateKey('test');
    }

    /**
     * @depends testGenericHash
     * @expectedException SimpleAPISecurity\PHP\Exceptions\OutOfRangeException
     * @expectedExceptionMessageRegExp #hash length range: \d+ to \d+#
     */
    public function testGenerateHashExceptionHigh()
    {
        Hash::hash('test', '', Constants::GENERICHASH_BYTES_MAX + 1);
    }

    /**
     * @depends testGenericHash
     * @expectedException SimpleAPISecurity\PHP\Exceptions\OutOfRangeException
     * @expectedExceptionMessageRegExp #hash length range: \d+ to \d+#
     */
    public function testGenerateHashExceptionLow()
    {
        Hash::hash('test', '', Constants::GENERICHASH_BYTES_MIN - 1);
    }

    /**
     * @depends testGenericHash
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Expected integer parameter for length in hash
     */
    public function testGenerateHashExceptionBadValue()
    {
        Hash::hash('test', '', 'test');
    }

    /**
     * @depends testGenericHash
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Expected string parameter for message in hash
     */
    public function testGenerateHashExceptionBadValueMessage()
    {
        Hash::hash(1);
    }

    /**
     * @depends testGenericHash
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Expected string parameter for key in hash
     */
    public function testGenerateHashExceptionBadValueKey()
    {
        Hash::hash('test', 1);
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

    /**
     * @depends testShortHash
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Expected string parameter for message in shortHash
     */
    public function testShortHashBadMessage()
    {
        $key = Hash::generateKey(Constants::GENERICHASH_KEYBYTES_MIN);
        Hash::shortHash(1, $key);
    }

    /**
     * @depends testShortHash
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Expected string parameter for key in shortHash
     */
    public function testShortHashBadKey()
    {
        Hash::shortHash('test', 1);
    }

    /**
     * @requires extension libsodium
     */
    public function passwordTest()
    {
        $password = 'testing';
        $passwordHash = Hash::hashPassword($password);
        $this->assertTrue(Hash::verifyPassword($password, $passwordHash));
        $this->assertFalse(Hash::verifyPassword('notcorrect', $passwordHash));
    }

    /**
     * @depends passwordTest
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Expected string parameter for password in verifyPassword
     */
    public function passwordTestBadPassword()
    {
        $password = 'testing';
        $passwordHash = Hash::hashPassword($password);
        Hash::verifyPassword(1, $passwordHash);
    }

    /**
     * @depends passwordTest
     * @expectedException SimpleAPISecurity\PHP\Exceptions\InvalidTypeException
     * @expectedExceptionMessage Expected string parameter for passwordHash in verifyPassword
     */
    public function passwordTestBashPasswordHash()
    {
        $password = 'testing';
        Hash::verifyPassword($password, 1);
    }
}