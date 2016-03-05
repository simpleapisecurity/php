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
     * Returns a string of random bytes to the client.
     *
     * @param int $bytes Size of the string of bytes to be generated.
     * @return string
     * @throws InvalidTypeException
     * @throws \Exception
     */
    static function bytes($bytes = Constants::BYTES)
    {
        # Filter the input to validate that we're an integer in range
        $filteredInput = filter_var($bytes, FILTER_VALIDATE_INT, [
            'options' => [
                'min_range' => Constants::BYTES_MIN,
                'max_range' => Constants::BYTES_MAX,
            ],
        ]);

        # Test if the input is an integer.
        if (is_integer($bytes)) {
            if ($filteredInput) {
                return \Sodium\randombytes_buf($bytes);
            } else {
                throw new OutOfRangeException('Bytes range: ' . Constants::BYTES_MIN . ' to ' . Constants::BYTES_MAX);
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
    static function integer($range = Constants::RANGE)
    {
        # Filter the input to validate that we're an integer in range
        $filteredInput = filter_var($range, FILTER_VALIDATE_INT, [
            'options' => [
                'min_range' => Constants::RANGE_MIN,
                'max_range' => Constants::RANGE_MAX,
            ],
        ]);

        # Test if the input is an integer.
        if (is_integer($range)) {
            if ($filteredInput) {
                return \Sodium\randombytes_uniform($filteredInput) + 1;
            } else {
                throw new OutOfRangeException('Integer range: ' . Constants::RANGE_MIN . ' to ' . Constants::RANGE_MAX);
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