/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"
#include "crypto_auth_algos.h"


/**
 * Register function calls in node binding
 */
void register_crypto_auth(Napi::Env env, Napi::Object exports) {

    // Auth
    EXPORT_ALIAS(crypto_auth, crypto_auth_hmacsha512256);
    EXPORT_ALIAS(crypto_auth_verify, crypto_auth_hmacsha512256_verify);
    EXPORT_ALIAS(crypto_auth_keygen, crypto_auth_hmacsha512256_keygen);

    EXPORT_INT(crypto_auth_BYTES);
    EXPORT_INT(crypto_auth_KEYBYTES);
    EXPORT_STRING(crypto_auth_PRIMITIVE);
}