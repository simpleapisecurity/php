<?php

namespace SimpleAPISecurity\PHP;

use SimpleAPISecurity\PHP\Exceptions\InvalidTypeException;
use SimpleAPISecurity\PHP\Exceptions\OutOfRangeException;

class Hash
{
    /**
     * Generates a hashing key for further repeatable hashes.
     *
     * @param int $length Length of the key being generated for hashing.
     * @return string
     * @throws InvalidTypeException
     * @throws OutOfRangeException
     */
    public static function generateKey($length = Constants::GENERICHASH_KEYBYTES)
    {
        # Filter the input to ensure length validity.
        $filteredInput = filter_var($length, FILTER_VALIDATE_INT, [
            'options' => [
                'min_range' => Constants::GENERICHASH_KEYBYTES_MIN,
                'max_range' => Constants::GENERICHASH_KEYBYTES_MAX,
            ],
        ]);

        # Check to make sure we're an integer.
        if (is_integer($length)) {
            if ($filteredInput) {
                return self::hash(Entropy::bytes($filteredInput), '', $length);
            } else {
                throw new OutOfRangeException('generateKey length range: '.Constants::GENERICHASH_KEYBYTES_MIN.' to '.Constants::GENERICHASH_KEYBYTES_MAX);
            }
        } else {
            throw new InvalidTypeException('Expected integer parameter for generateKey');
        }
    }

    /**
     * Hash a message and return a string.
     *
     * @param string $msg The message to be hashed.
     * @param string $key The key for the message to be hashed against.
     * @param int $length The length of the hash digest.
     * @return string
     * @throws InvalidTypeException
     * @throws OutOfRangeException
     */
    public static function hash($msg, $key = '', $length = Constants::GENERICHASH_BYTES)
    {
        # Filter the input to ensure length validity.
        $filteredInput = filter_var($length, FILTER_VALIDATE_INT, [
            'options' => [
                'min_range' => Constants::GENERICHASH_BYTES_MIN,
                'max_range' => Constants::GENERICHASH_BYTES_MAX,
            ],
        ]);

        # Check to make sure the $msg variable is a string.
        if (!is_string($msg)) {
            throw new InvalidTypeException('Expected string parameter for message in hash');
        }

        # Check to make sure the $key variable is a string.
        if (!is_string($key)) {
            throw new InvalidTypeException('Expected string parameter for key in hash');
        }

        # Check to make sure we're an integer.
        if (is_integer($length)) {
            if ($filteredInput) {
                return \Sodium\crypto_generichash($msg, $key, $filteredInput);
            } else {
                throw new OutOfRangeException('hash length range: '.Constants::GENERICHASH_BYTES_MIN.' to '.Constants::GENERICHASH_BYTES_MAX);
            }
        } else {
            throw new InvalidTypeException('Expected integer parameter for length in hash');
        }
    }

    /**
     * Quickly hash the message using the assigned key using randomness.
     *
     * @param string $msg The message to be short hashed.
     * @param string $key The key to hash the message against.
     * @return string
     * @throws InvalidTypeException
     */
    public static function shortHash($msg, $key)
    {
        # Check to make sure the $msg variable is a string.
        if (!is_string($msg)) {
            throw new InvalidTypeException('Expected string parameter for message in shortHash');
        }

        # Check to make sure the $key variable is a string.
        if (!is_string($key)) {
            throw new InvalidTypeException('Expected string parameter for key in shortHash');
        }

        return \Sodium\crypto_shorthash($msg, $key);
    }

    /**
     * Hashes a password for storage and later comparison.
     *
     * @param string $password The password to be hashed for storage.
     * @return string
     * @throws InvalidTypeException
     */
    public static function hashPassword($password)
    {
        # Check to make sure the $msg variable is a string.
        if (!is_string($password)) {
            throw new InvalidTypeException('Expected string parameter for password in hashPassword');
        }

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
     * @throws InvalidTypeException
     */
    public static function verifyPassword($password, $passwordHash)
    {
        # Check to make sure the $msg variable is a string.
        if (!is_string($password)) {
            throw new InvalidTypeException('Expected string parameter for password in verifyPassword');
        }

        # Check to make sure the $msg variable is a string.
        if (!is_string($passwordHash)) {
            throw new InvalidTypeException('Expected string parameter for passwordHash in verifyPassword');
        }

        if (\Sodium\crypto_pwhash_scryptsalsa208sha256_str_verify($passwordHash, $password)) {
            \Sodium\memzero($password);

            return true;
        } else {
            \Sodium\memzero($password);

            return false;
        }
    }
}