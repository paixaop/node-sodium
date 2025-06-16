/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * int crypto_hash(
 *    unsigned char * hbuf,
 *    const unsigned char * msg,
 *    unsigned long long mlen)
 */
NAPI_METHOD(crypto_hash) {
    Napi::Env env = info.Env();

    ARGS(1, "argument message must be a buffer");
    ARG_TO_UCHAR_BUFFER(msg);

    NEW_BUFFER_AND_PTR(hash, crypto_hash_BYTES);

    if( crypto_hash(hash_ptr, msg, msg_size) == 0 ) {
        return hash;
    } else {
        return NAPI_NULL;
    }
}

NAPI_METHOD_FROM_INT(crypto_hash_bytes)
NAPI_METHOD_FROM_STRING(crypto_hash_primitive)

/**
 * Register function calls in node binding
 */
void register_crypto_hash(Napi::Env env, Napi::Object exports) {
    
    // Hash
    EXPORT(crypto_hash);
    EXPORT(crypto_hash_bytes);
    EXPORT(crypto_hash_primitive);   
    EXPORT_INT(crypto_hash_BYTES);
    EXPORT_STRING(crypto_hash_PRIMITIVE);   
}