<?php

namespace SimpleAPISecurity\PHP;

/**
 * Class Helpers
 * @package SimpleAPISecurity\PHP
 */
class Helpers
{
    /**
     * Converts binary data to hexadecimal data.
     *
     * @param string $string String containing binary data to convert to hexadecimal.
     * @return string
     */
    public static function bin2hex($string)
    {
        return \Sodium\bin2hex($string);
    }

    /**
     * Converts hexadecimal data to binary data.
     *
     * @param string $string String containing hexadecimal data to convert to binary.
     * @param string $ignore String characters to ignore in binary conversion.
     * @return string
     */
    public static function hex2bin($string, $ignore = '')
    {
        return \Sodium\hex2bin($string, $ignore);
    }

    /**
     * Converts an IPv6 address to binary.
     *
     * @param string $ipv6 IPv6 address to convert to binary.
     * @return string
     */
    public static function ipv6ToBinary($ipv6)
    {
        return self::hex2bin($ipv6, ':');
    }

    /**
     * Converts a mac address to binary.
     *
     * @param string $mac Converts a system mac address to binary.
     * @return string
     */
    public static function macToBinary($mac)
    {
        return self::hex2bin($mac, ':');
    }

    /**
     * Increments a nonce to prevent replay attacks.
     *
     * @param string $string Random byte buffer with nonce.
     * @return void
     */
    public static function incrementNonce($string)
    {
        \Sodium\increment($string);
    }

    /**
     * Determines if a nonce is being replayed or not.
     *
     * @param string $previous_string Previous string with a nonce to compare.
     * @param string $current_string Current string with a nonce to compare.
     * @return string
     */
    public static function nonceCheck($previous_string, $current_string)
    {
        # Start the comparison
        $comparison = \Sodium\compare($previous_string, $current_string);

        # Switch for potential values
        switch ($comparison) {
            case -1:
                return 'MSG_PROGRESSED';
            case 0:
                return 'MSG_SAME';
            case 1:
                return 'MSG_FAST_FORWARD';
            default:
                return 'NONCE_UNKNOWN';
        }
    }

    /**
     * Compare two strings in constant time.
     *
     * @param string $string1 The first string to compare.
     * @param string $string2 The second string to compare.
     * @return bool
     */
    public static function stringCompare($string1, $string2)
    {
        if (\Sodium\memcmp($string1, $string2) !== 0) {
            return false;
        }

        return true;
    }
}