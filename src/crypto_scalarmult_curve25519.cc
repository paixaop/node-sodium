/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n)
 */
Napi::Value bind_crypto_scalarmult_curve25519_base(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(1,"argument must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(n, crypto_scalarmult_curve25519_SCALARBYTES);
    
    NEW_BUFFER_AND_PTR(q, crypto_scalarmult_curve25519_BYTES);

    if (crypto_scalarmult_curve25519_base(q_ptr, n) == 0) {
        return q;
    } else {
        return env.Null();
    }
}


/**
 * int crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
 *                  const unsigned char *p)
 */
Napi::Value bind_crypto_scalarmult_curve25519(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(2,"arguments must be buffers");
    ARG_TO_UCHAR_BUFFER_LEN(n, crypto_scalarmult_curve25519_SCALARBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(p, crypto_scalarmult_curve25519_BYTES);

    NEW_BUFFER_AND_PTR(q, crypto_scalarmult_curve25519_BYTES);

    if (crypto_scalarmult_curve25519(q_ptr, n, p) == 0) {
        return q;
    } else {
        return env.Null();
    }
}

/**
 * Register function calls in node binding
 */
void register_crypto_scalarmult_curve25519(Napi::Env env, Napi::Object exports) {

    // Scalar Mult
    NEW_METHOD(crypto_scalarmult_curve25519);
    NEW_METHOD(crypto_scalarmult_curve25519_base);
    NEW_INT_PROP(crypto_scalarmult_curve25519_SCALARBYTES);
    NEW_INT_PROP(crypto_scalarmult_curve25519_BYTES);
}