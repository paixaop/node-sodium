/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"
#include "crypto_onetimeauth_poly1305.h"

/**
 * Register function calls in node binding
 */
void register_crypto_onetimeauth(Napi::Env env, Napi::Object exports) {

    EXPORT_ALIAS(crypto_onetimeauth, crypto_onetimeauth_poly1305);
    EXPORT_ALIAS(crypto_onetimeauth_verify, crypto_onetimeauth_poly1305_verify);
    EXPORT_ALIAS(crypto_onetimeauth_init, crypto_onetimeauth_poly1305_init);
    EXPORT_ALIAS(crypto_onetimeauth_update, crypto_onetimeauth_poly1305_update);
    EXPORT_ALIAS(crypto_onetimeauth_final, crypto_onetimeauth_poly1305_final);
    EXPORT_ALIAS(crypto_onetimeauth_keygen, crypto_onetimeauth_poly1305_keygen);

    EXPORT_INT(crypto_onetimeauth_BYTES);
    EXPORT_INT(crypto_onetimeauth_KEYBYTES);
    EXPORT_STRING(crypto_onetimeauth_PRIMITIVE);
}