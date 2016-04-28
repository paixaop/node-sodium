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
 * crypto_auth:
 * ## crypto_auth_verify
 *
 * This is just an alias to the current crypto auth implementation
 * which is HMAC-SHA512-256. So the API is the same as
 * [crypto_auth_hmacsha512256](crypto_auth_algos.md/#crypto_auth_hmacsha512256)
 * and [crypto_auth_hmacsha512256_verify](crypto_auth_algos.md/#crypto_auth_hmacsha512256_verify)
 *
 * Please take a look at those for more details on using the API.
 *
 * ### Constants
 *
 * ~ crypto_auth_BYTES: length of hash buffer
 * ~ crypto_auth_KEYBYTES: length of hash secret key
 * ~ crypto_auth_PRIMITIVE: string with the name of the HMAC Primitive used by
 *   this API. Currently `hmacsha512256`.
 */

/*
 * Register function calls in node binding
 */
void register_crypto_auth(Handle<Object> target) {
    // Auth
    NEW_METHOD_ALIAS(crypto_auth, crypto_auth_hmacsha512256);
    NEW_METHOD_ALIAS(crypto_auth_verify, crypto_auth_hmacsha512256_verify);

    NEW_INT_PROP(crypto_auth_BYTES);
    NEW_INT_PROP(crypto_auth_KEYBYTES);
    NEW_STRING_PROP(crypto_auth_PRIMITIVE);
}
