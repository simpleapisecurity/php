<?php

namespace SimpleAPISecurity\PHP;

/**
 * A simple drop in hashing library for nearly any application. Uses sodium for hashing operations
 * in such a way that allow for safe and tamper resistant hashing actions.
 *
 * @package SimpleAPISecurity\PHP
 * @license http://opensource.org/licenses/MIT MIT
 */
class Hash
{
    /**
     * Generates a hashing key for further repeatable hashes.
     *
     * @param int $length Length of the key being generated for hashing.
     * @return string
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\OutOfRangeException
     */
    public static function generateKey($length = Constants::GENERICHASH_KEYBYTES)
    {
        # Test the length for validity.
        Helpers::rangeCheck($length, Constants::GENERICHASH_KEYBYTES_MAX, Constants::GENERICHASH_KEYBYTES_MIN, 'Hash', 'generateKey');

        # Return the hash to the client.
        return self::hash(Entropy::bytes($length), '', $length);
    }

    /**
     * Hash a message and return a string.
     *
     * @param string $msg The message to be hashed.
     * @param string $key The key for the message to be hashed against.
     * @param int $length The length of the hash digest.
     * @return string
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\OutOfRangeException
     */
    public static function hash($msg, $key = '', $length = Constants::GENERICHASH_BYTES)
    {
        # Test the length for validity.
        Helpers::rangeCheck($length, Constants::GENERICHASH_BYTES_MAX, Constants::GENERICHASH_BYTES_MIN, 'Hash', 'hash');

        # Test the message and key for string validity.
        Helpers::isString($msg, 'Hash', 'hash');
        Helpers::isString($key, 'Hash', 'hash');

        # Return the hash to the client.
        return \Sodium\crypto_generichash($msg, $key, $length);
    }

    /**
     * Quickly hash the message using the assigned key using randomness.
     *
     * @param string $msg The message to be short hashed.
     * @param string $key The key to hash the message against.
     * @return string
     * @throws Exceptions\InvalidTypeException
     */
    public static function shortHash($msg, $key)
    {
        # Test the message and key for string validity.
        Helpers::isString($msg, 'Hash', 'shortHash');
        Helpers::isString($key, 'Hash', 'shortHash');

        return \Sodium\crypto_shorthash($msg, $key);
    }

    /**
     * Hashes a password for storage and later comparison.
     *
     * @param string $password The password to be hashed for storage.
     * @return string
     * @throws Exceptions\InvalidTypeException
     */
    public static function hashPassword($password)
    {
        # Test the message and key for string validity.
        Helpers::isString($password, 'Hash', 'hashPassword');

        return \Sodium\crypto_pwhash_scryptsalsa208sha256_str(
            $password,
            Constants::PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            Constants::PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
        );
    }

    /**
     * Test if a password is valid against it's stored hash.
     *
     * @param string $password The client provided password to check.
     * @param string $passwordHash The saved password hash for comparison.
     * @return bool
     * @throws Exceptions\InvalidTypeException
     */
    public static function verifyPassword($password, $passwordHash)
    {
        # Test the message and key for string validity.
        Helpers::isString($password, 'Hash', 'verifyPassword');
        Helpers::isString($passwordHash, 'Hash', 'verifyPassword');

        if (\Sodium\crypto_pwhash_scryptsalsa208sha256_str_verify($passwordHash, $password)) {
            \Sodium\memzero($password);

            return true;
        } else {
            \Sodium\memzero($password);

            return false;
        }
    }
}