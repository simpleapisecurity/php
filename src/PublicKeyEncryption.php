<?php

namespace SimpleAPISecurity\PHP;

use SimpleAPISecurity\PHP\Exceptions\DecryptionException;
use SimpleAPISecurity\PHP\Exceptions\InvalidTypeException;
use SimpleAPISecurity\PHP\Exceptions\SignatureException;

/**
 * This class is specifically for creating a public/private keyring relationship
 * and sending data in such a way that the message is either fully encrypted
 * or signed for verification. This type of communication works similar to how
 * gpg currently functions.
 *
 * @package SimpleAPISecurity\PHP
 * @license http://opensource.org/licenses/MIT MIT
 */
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
            # Generate some repeatable hashes to create keys against for recovery
            $encrHash = Hash::hash($seed, $hashKey, Constants::BOX_SEEDBYTES);
            $signHash = Hash::hash($seed, $hashKey, Constants::SIGN_SEEDBYTES);

            # Build recoverable pre-seeded key pairs.
            $seeds = [
                'encr' => \Sodium\crypto_box_keypair($encrHash),
                'sign' => \Sodium\crypto_sign_keypair($signHash),
            ];
        } else {
            # Build un-recoverable key pairs.
            $seeds = [
                'encr' => \Sodium\crypto_box_keypair(),
                'sign' => \Sodium\crypto_sign_keypair(),
            ];
        }

        # Return the two generated key pairs to the client.
        return [
            'encr' => [
                'pri' => Helpers::bin2hex(\Sodium\crypto_box_secretkey($seeds['encr'])),
                'pub' => Helpers::bin2hex(\Sodium\crypto_box_publickey($seeds['encr'])),
            ],
            'sign' => [
                'pri' => Helpers::bin2hex(\Sodium\crypto_sign_secretkey($seeds['sign'])),
                'pub' => Helpers::bin2hex(\Sodium\crypto_sign_publickey($seeds['sign'])),
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
     * @throws InvalidTypeException
     */
    public static function encrypt($message, $sender_private, $receiver_public)
    {
        # Test to make sure all the required variables are strings.
        Helpers::isString($message, 'PublicKeyEncryption', 'encrypt');
        Helpers::isString($sender_private, 'PublicKeyEncryption', 'encrypt');
        Helpers::isString($receiver_public, 'PublicKeyEncryption', 'encrypt');

        # Generate a keypair for the message to be sent.
        $messageKeyPair = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
            Helpers::hex2bin($sender_private),
            Helpers::hex2bin($receiver_public)
        );

        # Generate the nonce for usage.
        $nonce = Entropy::generateNonce();

        # Encrypt the message and return it.
        return base64_encode(json_encode([
            'msg'   => Helpers::bin2hex(\Sodium\crypto_box(
                $message,
                $nonce,
                $messageKeyPair
            )),
            'nonce' => Helpers::bin2hex($nonce),
        ]));

    }

    /**
     * Decrypt a public key encrypted message.
     *
     * @param string $message The message to be encrypted.
     * @param string $sender_public The senders public key.
     * @param string $receiver_private The receivers private key.
     * @return string The JSON string for the encrypted message.
     * @throws DecryptionException
     * @throws InvalidTypeException
     */
    public static function decrypt($message, $sender_public, $receiver_private)
    {
        # Test to make sure all the required variables are strings.
        Helpers::isString($message, 'PublicKeyEncryption', 'decrypt');
        Helpers::isString($sender_public, 'PublicKeyEncryption', 'decrypt');
        Helpers::isString($receiver_private, 'PublicKeyEncryption', 'decrypt');

        # Generate a keypair for the message to be received.
        $messageKeyPair = \Sodium\crypto_box_keypair_from_secretkey_and_publickey(
            Helpers::hex2bin($receiver_private),
            Helpers::hex2bin($sender_public)
        );

        # Deconstruct the message from JSON.
        $message = base64_decode(json_decode($message, true));

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

    /**
     * @param string $message
     * @param string $signer_private
     * @return string The signature of the message.
     * @throws InvalidTypeException
     */
    public static function sign($message, $signer_private)
    {
        # Test to make sure all the required variables are strings.
        Helpers::isString($message, 'PublicKeyEncryption', 'sign');
        Helpers::isString($signer_private, 'PublicKeyEncryption', 'sign');

        return base64_encode(Helpers::bin2hex(\Sodium\crypto_sign_detached($message, $signer_private)));
    }

    /**
     * @param string $message
     * @param string $signature
     * @param string $signer_public
     * @return bool
     * @throws SignatureException
     * @throws InvalidTypeException
     */
    public static function verify($message, $signature, $signer_public)
    {
        # Test to make sure all the required variables are strings.
        Helpers::isString($message, 'PublicKeyEncryption', 'verify');
        Helpers::isString($signature, 'PublicKeyEncryption', 'verify');
        Helpers::isString($signer_public, 'PublicKeyEncryption', 'verify');

        # Decode the signature from hex
        $signature = base64_decode(Helpers::hex2bin($signature));

        # Decode the signer's public key from hex
        $signer_public = Helpers::hex2bin($signer_public);

        if (\Sodium\crypto_sign_verify_detached($signature, $message, $signer_public)) {
            return true;
        } else {
            throw new SignatureException('Signature for message invalid.');
        }
    }
}