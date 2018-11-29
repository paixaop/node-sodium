/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * int crypto_hash_sha512(
 *    unsigned char * hbuf,
 *    const unsigned char * msg,
 *    unsigned long long mlen)
 */
NAPI_METHOD(crypto_hash_sha512) {
    Napi::Env env = info.Env();

    ARGS(1, "argument message must be a buffer");
    ARG_TO_UCHAR_BUFFER(msg);

    NEW_BUFFER_AND_PTR(hash, crypto_hash_sha512_BYTES);

    if( crypto_hash_sha512(hash_ptr, msg, msg_size) == 0 ) {
        return hash;
    }

    return NAPI_NULL;
}

/*
 * int crypto_hash_sha512_init(crypto_hash_sha512_state *state);
 */
NAPI_METHOD(crypto_hash_sha512_init) {
    Napi::Env env = info.Env();

    NEW_BUFFER_AND_PTR(state, crypto_hash_sha512_statebytes());

    if( crypto_hash_sha512_init((crypto_hash_sha512_state*) state_ptr) == 0 ) {
        return state;
    }

    return NAPI_NULL;
}

/* int crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);

    Buffer state
    Buffer inStr
 */
NAPI_METHOD(crypto_hash_sha512_update) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be two buffers: hash state, message part");
    ARG_TO_UCHAR_BUFFER_LEN(state, crypto_hash_sha512_statebytes());
    ARG_TO_UCHAR_BUFFER(msg);

    if( crypto_hash_sha512_update((crypto_hash_sha512_state*)state, msg, msg_size) == 0 ) {
            return NAPI_TRUE;
    }
    return NAPI_FALSE;
}

/* int crypto_hash_sha512_final(crypto_hash_sha512_state *state,
                             unsigned char *out);

 */
NAPI_METHOD(crypto_hash_sha512_final) {
    Napi::Env env = info.Env();

    ARGS(1, "arguments must be a hash state buffer");
    ARG_TO_UCHAR_BUFFER(state);  // VOID
    NEW_BUFFER_AND_PTR(hash, crypto_hash_sha512_BYTES);

    if( crypto_hash_sha512_final((crypto_hash_sha512_state*) state, hash_ptr) == 0 ) {
        return hash;
    }

    return NAPI_NULL;
}

NAPI_METHOD_FROM_INT(crypto_hash_sha512_bytes)
NAPI_METHOD_FROM_INT(crypto_hash_sha512_statebytes)

/**
 * Register function calls in node binding
 */
void register_crypto_hash_sha512(Napi::Env env, Napi::Object exports) {

    // Hash
    EXPORT(crypto_hash_sha512);
    EXPORT(crypto_hash_sha512_init);
    EXPORT(crypto_hash_sha512_update);
    EXPORT(crypto_hash_sha512_final);
    EXPORT(crypto_hash_sha512_bytes);
    EXPORT(crypto_hash_sha512_statebytes);
    EXPORT_INT(crypto_hash_sha512_BYTES);
}