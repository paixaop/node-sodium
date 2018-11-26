/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

#include "crypto_streams.h"

NAPI_METHOD_FROM_INT(crypto_stream_keybytes)
NAPI_METHOD_FROM_INT(crypto_stream_noncebytes)
NAPI_METHOD_FROM_STRING(crypto_stream_primitive)

/**
 * Register function calls in node binding
 */
void register_crypto_stream(Napi::Env env, Napi::Object exports) {    

    // Stream
    EXPORT_ALIAS(crypto_stream, crypto_stream_xsalsa20);
    EXPORT_ALIAS(crypto_stream_xor, crypto_stream_xsalsa20_xor);

    EXPORT(crypto_stream_keybytes);
    EXPORT(crypto_stream_noncebytes);
    EXPORT(crypto_stream_primitive);
    
    EXPORT_INT(crypto_stream_KEYBYTES);
    EXPORT_INT(crypto_stream_NONCEBYTES);
    EXPORT_STRING(crypto_stream_PRIMITIVE);
}