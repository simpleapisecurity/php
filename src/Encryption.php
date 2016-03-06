<?php

namespace SimpleAPISecurity\PHP;

/**
 * The Encryption class provides standard key based and reversible encryption methods
 * which are safe to use in an API client for moving data in a secure way.
 *
 * @package SimpleAPISecurity\PHP
 * @license http://opensource.org/licenses/MIT MIT
 */
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
        # Test the message and key for string validity.
        Helpers::isString($message, 'Encryption', 'encryptMessage');
        Helpers::isString($key, 'Encryption', 'encryptMessage');
        Helpers::isString($hashKey, 'Encryption', 'encryptMessage');

        # Create a special hashed key for encryption.
        $key = Hash::hash($key, $hashKey, Constants::SECRETBOX_KEYBYTES);

        # Generate a nonce for the communication.
        $nonce = Entropy::generateNonce();

        return base64_encode(json_encode([
            'msg'   => Helpers::bin2hex(\Sodium\crypto_secretbox($message, $nonce, $key)),
            'nonce' => Helpers::bin2hex($nonce),
        ]));
    }

    /**
     * Returns the encrypted message in plaintext format.
     *
     * @param string $message The encrypted message portion.
     * @param string $key The encryption key used with the message.
     * @param string $hashKey The key to hash the key with.
     * @return string The encrypted message in plaintext format.
     * @throws Exceptions\DecryptionException
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\OutOfRangeException
     */
    public static function decryptMessage($message, $key, $hashKey = '')
    {
        # Test the message and key for string validity.
        Helpers::isString($message, 'Encryption', 'decryptMessage');
        Helpers::isString($key, 'Encryption', 'decryptMessage');
        Helpers::isString($hashKey, 'Encryption', 'decryptMessage');

        # Create a special hashed key for encryption.
        $key = Hash::hash($key, $hashKey, Constants::SECRETBOX_KEYBYTES);

        $messagePacket = base64_decode(json_decode($message, true));

        # Open the secret box using the data provided.
        $plaintext = \Sodium\crypto_secretbox_open(
            Helpers::hex2bin($messagePacket['msg']),
            Helpers::hex2bin($messagePacket['nonce']),
            $key
        );

        # Test if the secret box returned usable data.
        if ($plaintext === false) {
            throw new Exceptions\DecryptionException('Failed to decrypt message using key');
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
        # Test the message and key for string validity.
        Helpers::isString($message, 'Encryption', 'signMessage');
        Helpers::isString($key, 'Encryption', 'signMessage');
        Helpers::isString($hashKey, 'Encryption', 'signMessage');

        # Create a special hashed key for encryption.
        $key = Hash::hash($key, $hashKey, Constants::AUTH_KEYBYTES);

        # Generate a MAC for the message.
        $mac = \Sodium\crypto_auth($message, $key);

        return base64_encode(json_encode([
            'mac' => Helpers::bin2hex($mac),
            'msg' => $message,
        ]));
    }

    /**
     * Validates a message signature and returns the signed message.
     *
     * @param string $message The signed message JSON string.
     * @param string $key The signing key used with the message.
     * @param string $hashKey The key to hash the key with.
     * @return string A string returning the output of the signed message.
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\SignatureException
     */
    public static function verifyMessage($message, $key, $hashKey = '')
    {
        # Test the message and key for string validity.
        Helpers::isString($message, 'Encryption', 'verifyMessage');
        Helpers::isString($key, 'Encryption', 'verifyMessage');
        Helpers::isString($hashKey, 'Encryption', 'verifyMessage');

        # Create a special hashed key for encryption.
        $key = Hash::hash($key, $hashKey, Constants::AUTH_KEYBYTES);

        # Decode the message from JSON.
        $message = base64_decode(json_decode($message, true));

        if (\Sodium\crypto_auth_verify(Helpers::hex2bin($message['mac']), $message['msg'], $key)) {
            \Sodium\memzero($key);

            return $message['msg'];
        } else {
            \Sodium\memzero($key);
            throw new Exceptions\SignatureException('Signature for message invalid.');
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
     * @throws Exceptions\InvalidTypeException
     */
    public static function encryptSignMessage($message, $encryptionKey, $signatureKey, $hashKey = '')
    {
        # Test the message and key for string validity.
        Helpers::isString($message, 'Encryption', 'encryptSignMessage');
        Helpers::isString($encryptionKey, 'Encryption', 'encryptSignMessage');
        Helpers::isString($signatureKey, 'Encryption', 'encryptSignMessage');
        Helpers::isString($hashKey, 'Encryption', 'encryptSignMessage');

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
     * @throws Exceptions\InvalidTypeException
     * @throws Exceptions\SignatureException
     */
    public static function decryptVerifyMessage($message, $encryptionKey, $signatureKey, $hashKey = '')
    {
        # Test the message and key for string validity.
        Helpers::isString($message, 'Encryption', 'decryptVerifyMessage');
        Helpers::isString($encryptionKey, 'Encryption', 'decryptVerifyMessage');
        Helpers::isString($signatureKey, 'Encryption', 'decryptVerifyMessage');
        Helpers::isString($hashKey, 'Encryption', 'decryptVerifyMessage');

        $message = self::verifyMessage($message, $signatureKey, $hashKey);

        return self::decryptMessage($message, $encryptionKey, $hashKey);
    }
}