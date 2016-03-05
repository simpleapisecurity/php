<?php

namespace SimpleAPISecurity\PHP;

use SimpleAPISecurity\PHP\Exceptions\DecryptionException;
use SimpleAPISecurity\PHP\Exceptions\SignatureException;

class Encryption
{
    /**
     * Returns a secure generated signing key to be used for messages.
     *
     * @return string
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\OutOfRangeException
     */
    public static function generateSigningKey()
    {
        return Entropy::bytes(Constants::AUTH_KEYBYTES);
    }

    /**
     * Returns an encrypted message in the form of a JSON string.
     *
     * @param string $message The message to be encrypted.
     * @param string $key The key to encrypt the message with.
     * @param string $hashKey The key to hash the key with.
     * @return string The JSON string for the encrypted message.
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\OutOfRangeException
     */
    public static function encryptMessage($message, $key, $hashKey = '')
    {
        # Create a special hashed key for encryption.
        $key = Hash::hash($key, $hashKey, Constants::SECRETBOX_KEYBYTES);

        # Generate a nonce for the communication.
        $nonce = Entropy::generateNonce();

        return json_encode([
            'msg'   => Helpers::bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
            'nonce' => Helpers::bin2hex($nonce),
        ]);
    }

    /**
     * Returns the encrypted message in plaintext format.
     *
     * @param string $message The encrypted message portion.
     * @param string $key The encryption key used with the message.
     * @param string $hashKey The key to hash the key with.
     * @return string The encrypted message in plaintext format.
     * @throws DecryptionException
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\OutOfRangeException
     */
    public static function decryptMessage($message, $key, $hashKey = '')
    {
        # Create a special hashed key for encryption.
        $key = Hash::hash($key, $hashKey, Constants::SECRETBOX_KEYBYTES);

        $messagePacket = json_decode($message, true);

        # Open the secret box using the data provided.
        $plaintext = \Sodium\crypto_secretbox_open(
            Helpers::hex2bin($messagePacket['msg']),
            Helpers::hex2bin($messagePacket['nonce']),
            $key
        );

        # Test if the secret box returned usable data.
        if ($plaintext === false) {
            throw new DecryptionException('Failed to decrypt message using key');
        }

        return $plaintext;
    }

    /**
     * Returns a signed message to the client for authentication.
     *
     * @param string $message The message to be signed.
     * @param string $key The signing key used with the message.
     * @param string $hashKey The key to hash the key with.
     * @return string A JSON string including the signing information and message.
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\OutOfRangeException
     */
    public static function signMessage($message, $key, $hashKey = '')
    {
        # Create a special hashed key for encryption.
        $key = Hash::hash($key, $hashKey, Constants::AUTH_KEYBYTES);

        # Generate a MAC for the message.
        $mac = \Sodium\crypto_auth($message, $key);

        return json_encode([
            'mac' => Helpers::bin2hex($mac),
            'msg' => $message,
        ]);
    }

    /**
     * Validates a message signature and returns the signed message.
     *
     * @param string $message The signed message JSON string.
     * @param string $key The signing key used with the message.
     * @param string $hashKey The key to hash the key with.
     * @return string A string returning the output of the signed message.
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\OutOfRangeException
     * @throws SignatureException
     */
    public static function verifyMessage($message, $key, $hashKey = '')
    {
        # Create a special hashed key for encryption.
        $key = Hash::hash($key, $hashKey, Constants::AUTH_KEYBYTES);

        # Decode the message from JSON.
        $message = json_decode($message, true);

        if (\Sodium\crypto_auth_verify(Helpers::hex2bin($message['mac']), $message['msg'], $key)) {
            \Sodium\memzero($key);

            return $message['msg'];
        } else {
            \Sodium\memzero($key);
            throw new SignatureException('Signature for message invalid.');
        }
    }

    /**
     * Sign and encrypt a message for security.
     *
     * @param string $message The message to be encrypted and signed for transport.
     * @param string $encryptionKey The encryption key used with the message.
     * @param string $signatureKey The signing key used with the message.
     * @param string $hashKey The key to hash the key with.
     * @return string The encrypted and signed JSON string with message data.
     */
    public static function encryptSignMessage($message, $encryptionKey, $signatureKey, $hashKey = '')
    {
        $message = self::encryptMessage($message, $encryptionKey, $hashKey);

        return self::signMessage($message, $signatureKey, $hashKey);
    }

    /**
     * Verify and decrypt a message for security.
     *
     * @param string $message The message to be encrypted and signed for transport.
     * @param string $encryptionKey The encryption key used with the message.
     * @param string $signatureKey The signing key used with the message.
     * @param string $hashKey The key to hash the key with.
     * @return string The string of the signed and decrypted message.
     */
    public static function decryptVerifyMessage($message, $encryptionKey, $signatureKey, $hashKey = '')
    {
        $message = self::verifyMessage($message, $signatureKey, $hashKey);

        return self::decryptMessage($message, $encryptionKey, $hashKey);
    }
}