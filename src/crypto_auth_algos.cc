/*
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"
#include "crypto_auth_algos.h"

/**
 * Secret Key Authentication
 *
 * Compute an authentication tag for a message and a secret key, and provides a
 * way to verify that a given tag is valid for a given message and a key.
 *
 * The function computing the tag deterministic:
 * the same (message, key) tuple will always produce the same output.
 *
 * However, even if the message is public, knowing the key is required in order
 * to be able to compute a valid tag. Therefore, the key should remain
 * confidential. The tag, however, can be public.
 *
 * This operation does not encrypt the message. It only computes and verifies an
 * authentication tag.
 *
 * Supported Algorithms:
 *
 *  * HMAC-SHA256: API names use `hmacsha256`
 *  * HMAC-SHA512: API names use `hmacsha512`
 *  * HMAC-SHA512256: API names use `hmacsha512256`
 *
 * **Sample**:
 *
 *     var sodium = require('sodium').api;
 *
 *     // Generate a random key
 *     var key = new Buffer(crypto_auth_KEYBYTES);
 *     sodium.randombytes_buf(key);
 *
 *     var message = new Buffer("this is a public text message");
 *
 *     // Generate auth tag
 *     var tag = sodium.crypto_auth_hmacsha512256(message, key);
 *
 *     if( sodium.crypto_auth_hmacsha512256_verify(tag, message, key) ) {
 *         console.log('Message authenticated');
 *     }
 *
 * The algorithm used in the code sample can be changed to any of the supported
 * algorithms.
 */

/**
 * crypto_auth_hmacsha512256:
 * Compute an authentication tag for `message` using a secret `key`
 *
 *     var tag = sodium.crypto_auth_hmacsha512256(message, key);
 *
 * ~ message (Buffer): plain text message to authenticate. Message is not
 *   encrypted by this function and remains in plain text
 * ~ key (Buffer): secret key , length must be `crypto_auth_hmacsha256_KEYBYTES`
 *   bytes
 *
 * **Returns**:
 *
 * ~ tag (Buffer): unique message authentication tag with length
 *   `crypto_auth_hmacsha256_BYTES` bytes
 *
 * See: [crypto_auth_hmacsha512256_verify](#crypto_auth_hmacsha512256_verify)
 */

 /**
  * crypto_auth_hmacsha512256_verify:
  * Compute an authentication tag for `message` using a secret `key`
  *
  *     var results = sodium.crypto_auth_hmacsha512256_verify(tag, message, key);
  *
  * ~ tag (Buffer): message authentication tag. Must be
  *   `crypto_auth_hmacsha256_BYTES` long.
  * ~ message (Buffer): plain text message to authenticate. Message is not
  *   encrypted by this function and remains in plain text
  * ~ key (Buffer): secret key , length must be `crypto_auth_hmacsha256_KEYBYTES`
  *   bytes
  *
  * **Returns**:
  *
  * ~ true: if it's able to match the message using tag.
  * ~ false: otherwize
  *
  * See: [crypto_auth_hmacsha512256](#crypto_auth_hmacsha512256)
  */
  
CRYPTO_AUTH_DEF(hmacsha256)
CRYPTO_AUTH_DEF(hmacsha512)
CRYPTO_AUTH_DEF(hmacsha512256)

/*
 * Register function calls in node binding
 */
void register_crypto_auth_algos(Handle<Object> target) {

    METHOD_AND_PROPS(hmacsha256)
    METHOD_AND_PROPS(hmacsha512)
    METHOD_AND_PROPS(hmacsha512256)
}
