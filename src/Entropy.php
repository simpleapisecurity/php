<?php

namespace SimpleAPISecurity\PHP;

use SimpleAPISecurity\PHP\Exceptions\InvalidTypeException;
use SimpleAPISecurity\PHP\Exceptions\OutOfRangeException;

/**
 * Class Entropy
 * @package SimpleAPISecurity\PHP
 */
class Entropy
{
    /**
     * The default amount of bytes to use for the bytes generator for entropy.
     * @const BYTES
     */
    const BYTES = 32;

    /**
     * The minimum amount of bytes to generate for the byte generator.
     * @const BYTES_MIN
     */
    const BYTES_MIN = 1;

    /**
     * The maximum amount of bytes to generate for the bytes generator.
     * @const BYTES_MAX
     */
    const BYTES_MAX = 255;

    /**
     * The default range for random integer selection for entropy.
     * @const RANGE
     */
    const RANGE = 100;

    /**
     * The minimum integer to create a range against.
     * @const RANGE_MIN
     */
    const RANGE_MIN = 1;

    /**
     * The maximum integer to create a range against.
     * @const RANGE_MAX
     */
    const RANGE_MAX = 2147483647;

    /**
     * Returns a string of random bytes to the client.
     *
     * @param int $bytes Size of the string of bytes to be generated.
     * @return string
     * @throws InvalidTypeException
     * @throws \Exception
     */
    static function bytes($bytes = self::BYTES)
    {
        # Filter the input to validate that we're an integer in range
        $filteredInput = filter_var($bytes, FILTER_VALIDATE_INT, [
            'options' => [
                'min_range' => self::BYTES_MIN,
                'max_range' => self::BYTES_MAX,
            ],
        ]);

        # Test if the input is an integer.
        if (is_integer($bytes)) {
            if ($filteredInput) {
                return \Sodium\randombytes_buf($bytes);
            } else {
                throw new OutOfRangeException('Bytes range: ' . self::BYTES_MIN . ' to ' . self::BYTES_MAX);
            }
        } else {
            throw new InvalidTypeException('Expected integer parameter for bytes');
        }
    }

    /**
     * Returns a random integer to the client.
     *
     * @param int $range Upper limit of random numbers to return to the client.
     * @return int
     * @throws InvalidTypeException
     * @throws OutOfRangeException
     */
    static function integer($range = self::RANGE)
    {
        # Filter the input to validate that we're an integer in range
        $filteredInput = filter_var($range, FILTER_VALIDATE_INT, [
            'options' => [
                'min_range' => self::RANGE_MIN,
                'max_range' => self::RANGE_MAX,
            ],
        ]);

        # Test if the input is an integer.
        if (is_integer($range)) {
            if ($filteredInput) {
                return \Sodium\randombytes_uniform($filteredInput) + 1;
            } else {
                throw new OutOfRangeException('Integer range: ' . self::RANGE_MIN . ' to ' . self::RANGE_MAX);
            }
        } else {
            throw new InvalidTypeException('Expected integer parameter for integer');
        }
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
}