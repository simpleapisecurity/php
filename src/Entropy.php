<?php

namespace SimpleAPISecurity\PHP;

use SimpleAPISecurity\PHP\Exceptions\InvalidTypeException;
use SimpleAPISecurity\PHP\Exceptions\OutOfRangeException;

/**
 * The Entropy class provides various methods to return random data to the API client.
 *
 * @package SimpleAPISecurity\PHP
 * @license http://opensource.org/licenses/MIT MIT
 * @todo Possibly rename this class because "Entropy" doesn't make a lot of sense, I don't think.
 */
class Entropy
{
    /**
     * Returns a string of random bytes to the client.
     *
     * @param int $bytes Size of the string of bytes to be generated.
     * @return string
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\OutOfRangeException
     */
    static function bytes($bytes = Constants::BYTES)
    {
        # Test the length for validity.
        Helpers::rangeCheck($bytes, Constants::BYTES_MAX, Constants::BYTES_MIN, 'Entropy', 'bytes');

        return \Sodium\randombytes_buf($bytes);
    }

    /**
     * Returns a random integer to the client.
     *
     * @param int $range Upper limit of random numbers to return to the client.
     * @return int
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\OutOfRangeException
     */
    static function integer($range = Constants::RANGE)
    {
        # Test the length for validity.
        Helpers::rangeCheck($range, Constants::RANGE_MAX, Constants::RANGE_MIN, 'Entropy', 'integer');

        return \Sodium\randombytes_uniform($range) + 1;
    }

    /**
     * Returns a random number from 0 to 65535 to the client.
     *
     * @return int
     */
    static function integer16()
    {
        return \Sodium\randombytes_random16();
    }

    /**
     * Return a secrete nonce string as entropy to the client.
     *
     * @return string
     */
    static function generateNonce()
    {
        return \Sodium\randombytes_buf(Constants::SECRETBOX_NONCEBYTES);
    }
}