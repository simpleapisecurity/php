<?php

namespace SimpleAPISecurity\PHP;

use SimpleAPISecurity\PHP\Exceptions\DecryptionException;

class PublicKeyEncryption
{
    /**
     * Returns a new set of keys for message encryption and signing.
     *
     * @param string $seed The seed to use to create repeatable keys.
     * @param string $hashKey The key to hash the key with.
     * @return array
     */
    public static function generateKeys($seed = null, $hashKey = '')
    {
        # The keys are being generated from a seed.
        if ($seed !== null) {
            $seedHash = Hash::hash($seed, $hashKey, Constants::BOX_SEEDBYTES);

            $seeds = [
                'encr' => \Sodium\crypto_box_keypair($seedHash),
                'sign' => \Sodium\crypto_sign_keypair($seedHash),
            ];
        } else {
            $seeds = [
                'encr' => \Sodium\crypto_box_keypair(),
                'sign' => \Sodium\crypto_sign_keypair(),
            ];
        }

        return [
            'encr' => [
                'pri' => \Sodium\crypto_box_secretkey($seeds['encr']),
                'pub' => \Sodium\crypto_box_publickey($seeds['encr']),
            ],
            'sign' => [
                'pri' => \Sodium\crypto_sign_secretkey($seeds['sign']),
                'pub' => \Sodium\crypto_sign_publickey($seeds['sign']),
            ],
        ];
    }

    /**
     * Encrypt a message using public key encryption.
     *
     * @param string $message The message to be encrypted.
     * @param string $sender_private The senders private key.
     * @param string $receiver_public The receivers public key.
     * @return string The JSON string for the encrypted message.
     */
    public static function encrypt($message, $sender_private, $receiver_public)
    {
        # Generate a keypair for the message to be sent.
        $messageKeyPair = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
            $sender_private,
            $receiver_public
        );

        # Generate the nonce for usage.
        $nonce = Entropy::generateNonce();

        # Encrypt the message and return it.
        return json_encode([
            'msg'   => Helpers::bin2hex(\Sodium\crypto_box(
                $message,
                $nonce,
                $messageKeyPair
            )),
            'nonce' => Helpers::bin2hex($nonce),
        ]);

    }

    /**
     * Decrypt a public key encrypted message.
     *
     * @param string $message The message to be encrypted.
     * @param string $sender_public The senders public key.
     * @param string $receiver_private The receivers private key.
     * @return string The JSON string for the encrypted message.
     * @throws DecryptionException
     */
    public static function decrypt($message, $sender_public, $receiver_private)
    {
        # Generate a keypair for the message to be received.
        $messageKeyPair = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
            $receiver_private,
            $sender_public
        );

        # Deconstruct the message from JSON.
        $message = json_decode($message, true);

        # Attempt to decrypt the message.
        $plaintext = \Sodium\crypto_box_open(
            Helpers::hex2bin($message['msg']),
            Helpers::hex2bin($message['nonce']),
            $messageKeyPair
        );

        # Test if the message was able to be decrypted.
        if ($plaintext === false) {
            throw new DecryptionException('Failed to decrypt message using key');
        }

        return $plaintext;
    }
}