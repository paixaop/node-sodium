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
 *  * HMAC-SHA512-256: API names use `hmacsha512256`
 *
 * ### Constants
 * Replace `ALGORITHM` with one of the supported algorithms (`hmacsha256`,
 * `hmacsha512`, or `hmacsha512256`)
 *
 * ~ crypto_auth_ALGORITHM_BYTES: length of hash buffer
 * ~ crypto_auth_ALGORITHM_KEYBYTES: length of hash secret key
 *
 * **Sample**:
 *
 *     var sodium = require('sodium').api;
 *
 *     // Generate a random key
 *     var key = new Buffer(crypto_auth_hmacsha512256_KEYBYTES);
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
 *
 * Only use these functions for interoperability with 3rd party services. For
 * everything else, you should probably use `crypto_auth()`/`crypto_auth_verify()`
 * or `crypto_generichash_*()` instead.
 */

/**
 * crypto_auth_ALGORITHM:
 * Compute an authentication tag for `message` using a secret `key`
 *
 * ~ ALGORITHM: depending on the desired algorithm call:
 *
 *  * crypto_auth_hmacsha512256
 *  * crypto_auth_hmacsha512
 *  * crypto_auth_hmacsha256
 *
 * All these functions have the same prototype, and functionality.
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
 * See: [crypto_auth_ALGORITHM_verify](#crypto_auth_ALGORITHM_verify)
 */

/**
 * crypto_auth_ALGORITHM_verify:
 * Compute an authentication tag for `message` using a secret `key`
 *
 * ~ ALGORITHM: depending on the desired algorithm call:
 *
 *  * crypto_auth_hmacsha512256_verify
 *  * crypto_auth_hmacsha512_verify
 *  * crypto_auth_hmacsha256_verify
 *
 * All these functions have the same prototype, and functionality.
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
 * See: [crypto_auth_ALGORITHM](#crypto_auth_ALGORITHM)
 */

/**
 * Streaming or Multi-Part API:
 * The streaming Authentication API allows to authenticate messages that may not be available
 * all at once. In this scenario call the `crypto_auth_ALGORITHM_init` followed
 * by one or multiple calls to `crypto_auth_ALGORITHM_update` and finally call
 * `crypto_auth_ALGORITHM_final` when the message parts have all been processed.
 *
 * Arbitrary key lengths are supported using the multi-part interface.
 * However, please note that in the HMAC construction, a key larger than the
 * block size gets reduced to h(key).
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
 *     // Same message as in previous example but broken down into parts
 *     var message1 = new Buffer("this is ");
 *     var message2 = new Buffer("a public ");
 *     var message3 = new Buffer("text message");
 *
 *     // Init streaming auth API
 *     var state = sodium.crypto_auth_hmacsha512256_init(key);
 *
 *     // Process each message part
 *     sodium.crypto_auth_hmacsha512256_update(state, message1);
 *     sodium.crypto_auth_hmacsha512256_update(state, message2);
 *     sodium.crypto_auth_hmacsha512256_update(state, message3);
 *
 *     // Call final after the last message part was processed
 *     var tag = sodium.crypto_auth_hmacsha512256_final(state);
 *
 * The algorithm used in the code sample can be changed to any of the supported
 * algorithms.
 */

/**
 * crypto_auth_ALGORITHM_init:
 * Initialize state Object
 *
 * ~ ALGORITHM: depending on the desired algorithm call:
 *
 *  * crypto_auth_hmacsha512256_init
 *  * crypto_auth_hmacsha512_init
 *  * crypto_auth_hmacsha256_init
 *
 * All these functions have the same prototype, and functionality.
 *
 *     var state = sodium.crypto_auth_ALGORITHM_init(key);
 *
 * ~ key (Buffer): secret key , can have arbitrary length, but it's reduced to
 * h(key) if bigger than hash block size.
 *
 * **Returns**:
 *
 * ~ state (Buffer): create nternal hash state, should only be used by
 *      `crypto_auth_ALGORITHM_update` and `crypto_auth_ALGORITHM_final`
 * ~ undefined: if state initialization fails
 *
 * See:
 *  * [crypto_auth_ALGORITHM_update](#crypto_auth_ALGORITHM_update)
 *  * [crypto_auth_ALGORITHM_final](#crypto_auth_ALGORITHM_final)
 */

/**
 * crypto_auth_ALGORITHM_update:
 * Update state with message part
 *
 * ~ ALGORITHM: depending on the desired algorithm call:
 *
 *  * crypto_auth_hmacsha512256_update
 *  * crypto_auth_hmacsha512_update
 *  * crypto_auth_hmacsha256_update
 *
 * All these functions have the same prototype, and functionality.
 *
 *     var state = sodium.crypto_auth_ALGORITHM_update(state, message_part);
 *
 * ~ state (Buffer): state buffer initialized by `_init` call.
 * ~ message_part (Buffer): part of the message that needs to be processed
 *
 * `state` can only be used after `_init()` has been called. `state` cannot be
 * used after `_final()` has been called without calling `_init()` again.
 *
 * **Returns**:
 *
 * ~ true: if operation succeeded
 * ~ false: otherwize
 *
 * See:
 *  * [crypto_auth_ALGORITHM_init](#crypto_auth_ALGORITHM_init)
 *  * [crypto_auth_ALGORITHM_final](#crypto_auth_ALGORITHM_final)
 */

/**
 * crypto_auth_ALGORITHM_final:
 * Finalize calculation
 *
 * ~ ALGORITHM: depending on the desired algorithm call:
 *
 *  * crypto_auth_hmacsha512256_final
 *  * crypto_auth_hmacsha512_final
 *  * crypto_auth_hmacsha256_final
 *
 * All these functions have the same prototype, and functionality.
 *
 *     var tag = sodium.crypto_auth_ALGORITHM_final(state);
 *
 * ~ state (Buffer): state buffer initialized by `_init` call.
 *
 * **YOU CANNOT USE THE `state` after this function is called.**
 *
 * `state` can only be used after `_init()` has been called. `state` cannot be
 * used after `_final()` has been called without calling `_init()` again.
 *
 * **Returns**:
 *
 * ~ tag (Buffer): authentication tag result of the hashing calculation
 * ~ undefined: if it fails
 *
 * See:
 *  * [crypto_auth_ALGORITHM_init](#crypto_auth_ALGORITHM_init)
 *  * [crypto_auth_ALGORITHM_update](#crypto_auth_ALGORITHM_update)
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
