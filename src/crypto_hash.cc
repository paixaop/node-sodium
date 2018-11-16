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
Napi::Value bind_crypto_hash(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(1,"argument message must be a buffer");
    ARG_TO_UCHAR_BUFFER(msg);

    NEW_BUFFER_AND_PTR(hash, crypto_hash_BYTES);

    if( crypto_hash(hash_ptr, msg, msg_size) == 0 ) {
        return hash;
    } else {
        return env.Null();
    }
}

/**
 * Register function calls in node binding
 */
void register_crypto_hash(Napi::Env env, Napi::Object exports) {
    
    // Hash
    NEW_METHOD(crypto_hash);
    NEW_INT_PROP(crypto_hash_BYTES);
    //NEW_INT_PROP(crypto_hash_BLOCKBYTES);
    NEW_STRING_PROP(crypto_hash_PRIMITIVE);   
}