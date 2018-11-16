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
Napi::Value bind_crypto_hash_sha512(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(1,"argument message must be a buffer");
    ARG_TO_UCHAR_BUFFER(msg);

    NEW_BUFFER_AND_PTR(hash, crypto_hash_sha512_BYTES);

    if( crypto_hash_sha512(hash_ptr, msg, msg_size) == 0 ) {
        return hash;
    }

    return env.Null();
}

/*
 * int crypto_hash_sha512_init(crypto_hash_sha512_state *state);
 */
Napi::Value bind_crypto_hash_sha512_init(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    NEW_BUFFER_AND_PTR(state, crypto_hash_sha512_statebytes());

    if( crypto_hash_sha512_init((crypto_hash_sha512_state*) state_ptr) == 0 ) {
        return state;
    }

    return env.Null();
}

/* int crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);

    Buffer state
    Buffer inStr
 */
Napi::Value bind_crypto_hash_sha512_update(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(2,"arguments must be two buffers: hash state, message part");
    ARG_TO_UCHAR_BUFFER(state);  // VOID
    ARG_TO_UCHAR_BUFFER(msg);

    NEW_BUFFER_AND_PTR(state2, crypto_hash_sha512_statebytes());
    memcpy(state2_ptr, state, crypto_hash_sha512_statebytes());

    if( crypto_hash_sha512_update((crypto_hash_sha512_state*)state2_ptr, msg, msg_size) == 0 ) {
        return state2;
    }

    return env.Null();
}

/* int crypto_hash_sha512_final(crypto_hash_sha512_state *state,
                             unsigned char *out);

 */
Napi::Value bind_crypto_hash_sha512_final(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(1,"arguments must be a hash state buffer");
    ARG_TO_UCHAR_BUFFER(state);  // VOID
    NEW_BUFFER_AND_PTR(hash, crypto_hash_sha256_BYTES);

    if( crypto_hash_sha512_final((crypto_hash_sha512_state*) state, hash_ptr) == 0 ) {
        return hash;
    }

    return Napi::Boolean::New(env, false);
}

/**
 * Register function calls in node binding
 */
void register_crypto_hash_sha512(Napi::Env env, Napi::Object exports) {

    // Hash
    NEW_METHOD(crypto_hash_sha512);
    NEW_METHOD(crypto_hash_sha512_init);
    NEW_METHOD(crypto_hash_sha512_update);
    NEW_METHOD(crypto_hash_sha512_final);
    NEW_INT_PROP(crypto_hash_sha512_BYTES);
}