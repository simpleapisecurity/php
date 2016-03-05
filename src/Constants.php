<?php

namespace SimpleAPISecurity\PHP;


class Constants
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
     * The message produced if a NONCE has progressed.
     * @const NONCE_MSG_PROGRESSED
     */
    const NONCE_MSG_PROGRESSED = 'MSG_PROGRESSED ';

    /**
     * The message produced if a NONCE is identical.
     * @const NONCE_MSG_SAME
     */
    const NONCE_MSG_SAME = 'MSG_SAME';

    /**
     * The message produced if a NONCE has fast forwarded.
     * @const NONCE_MSG_FAST_FORWARD
     */
    const NONCE_MSG_FAST_FORWARD = 'MSG_FAST_FORWARD';

    /**
     * The message produced if determining NONCE is impossible.
     * @const NONCE_UNKNOWN
     */
    const NONCE_UNKNOWN = 'NONCE_UNKNOWN';

    /**
     * Sodium Constants
     */
    const AEAD_AES256GCM_KEYBYTES = 32;
    const AEAD_AES256GCM_NSECBYTES = 0;
    const AEAD_AES256GCM_NPUBBYTES = 12;
    const AEAD_AES256GCM_ABYTES = 16;
    const AEAD_CHACHA20POLY1305_KEYBYTES = 32;
    const AEAD_CHACHA20POLY1305_NSECBYTES = 0;
    const AEAD_CHACHA20POLY1305_NPUBBYTES = 8;
    const AEAD_CHACHA20POLY1305_ABYTES = 16;
    const AUTH_BYTES = 32;
    const AUTH_KEYBYTES = 32;
    const BOX_SEALBYTES = 16;
    const BOX_SECRETKEYBYTES = 32;
    const BOX_PUBLICKEYBYTES = 32;
    const BOX_KEYPAIRBYTES = 64;
    const BOX_MACBYTES = 16;
    const BOX_NONCEBYTES = 24;
    const BOX_SEEDBYTES = 32;
    const KX_BYTES = 32;
    const KX_PUBLICKEYBYTES = 32;
    const KX_SECRETKEYBYTES = 32;
    const GENERICHASH_BYTES = 32;
    const GENERICHASH_BYTES_MIN = 16;
    const GENERICHASH_BYTES_MAX = 64;
    const GENERICHASH_KEYBYTES = 32;
    const GENERICHASH_KEYBYTES_MIN = 16;
    const GENERICHASH_KEYBYTES_MAX = 64;
    const PWHASH_SCRYPTSALSA208SHA256_SALTBYTES = 32;
    const PWHASH_SCRYPTSALSA208SHA256_STRPREFIX = '$7$';
    const PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE = 534288;
    const PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE = 16777216;
    const PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_SENSITIVE = 33554432;
    const PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_SENSITIVE = 1073741824;
    const SCALARMULT_BYTES = 32;
    const SCALARMULT_SCALARBYTES = 32;
    const SHORTHASH_BYTES = 8;
    const SHORTHASH_KEYBYTES = 16;
    const SECRETBOX_KEYBYTES = 32;
    const SECRETBOX_MACBYTES = 16;
    const SECRETBOX_NONCEBYTES = 24;
    const SIGN_BYTES = 64;
    const SIGN_SEEDBYTES = 32;
    const SIGN_PUBLICKEYBYTES = 32;
    const SIGN_SECRETKEYBYTES = 64;
    const SIGN_KEYPAIRBYTES = 96;
    const STREAM_KEYBYTES = 32;
    const STREAM_NONCEBYTES = 24;
}