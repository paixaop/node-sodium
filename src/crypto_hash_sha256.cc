/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * int crypto_hash_sha256(
 *    unsigned char * hbuf,
 *    const unsigned char * msg,
 *    unsigned long long mlen)
 */
NAPI_METHOD(crypto_hash_sha256) {
    Napi::Env env = info.Env();

    ARGS(1, "argument message must be a buffer");
    ARG_TO_UCHAR_BUFFER(msg);

    NEW_BUFFER_AND_PTR(hash, crypto_hash_sha256_BYTES);

    if( crypto_hash_sha256(hash_ptr, msg, msg_size) == 0 ) {
        return hash;
    }

    return NAPI_NULL;
}

/*
 * int crypto_hash_sha256_init(crypto_hash_sha256_state *state);
 */
NAPI_METHOD(crypto_hash_sha256_init) {
    Napi::Env env = info.Env();

    NEW_BUFFER_AND_PTR(state, crypto_hash_sha256_statebytes());

    if( crypto_hash_sha256_init((crypto_hash_sha256_state*) state_ptr) == 0 ) {
        return state;
    }

    return NAPI_NULL;
}

/* int crypto_hash_sha256_update(crypto_hash_sha256_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);

    Buffer state
    Buffer inStr
 */
NAPI_METHOD(crypto_hash_sha256_update) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be two buffers: hash state, message part");
    ARG_TO_UCHAR_BUFFER_LEN(state, crypto_hash_sha256_statebytes()); // VOID
    ARG_TO_UCHAR_BUFFER(msg);
    
    if( crypto_hash_sha256_update((crypto_hash_sha256_state*)state, msg, msg_size) == 0 ) {
            return NAPI_TRUE;
    }
    return NAPI_FALSE;
}

NAPI_METHOD_FROM_INT(crypto_hash_sha256_bytes)
NAPI_METHOD_FROM_INT(crypto_hash_sha256_statebytes)

/* int crypto_hash_sha256_final(crypto_hash_sha256_state *state,
                             unsigned char *out);

 */
NAPI_METHOD(crypto_hash_sha256_final) {
    Napi::Env env = info.Env();

    ARGS(1, "arguments must be a hash state buffer");
    ARG_TO_UCHAR_BUFFER(state);  // VOID
    NEW_BUFFER_AND_PTR(hash, crypto_hash_sha256_BYTES);

    if( crypto_hash_sha256_final((crypto_hash_sha256_state*)state, hash_ptr) == 0 ) {
        return hash;
    }

    return NAPI_FALSE;
}

/**
 * Register function calls in node binding
 */
void register_crypto_hash_sha256(Napi::Env env, Napi::Object exports) {

    // Hash
    EXPORT(crypto_hash_sha256);
    EXPORT(crypto_hash_sha256_init);
    EXPORT(crypto_hash_sha256_update);
    EXPORT(crypto_hash_sha256_final);
    EXPORT(crypto_hash_sha256_bytes);
    EXPORT(crypto_hash_sha256_statebytes);
    EXPORT_INT(crypto_hash_sha256_BYTES);
}