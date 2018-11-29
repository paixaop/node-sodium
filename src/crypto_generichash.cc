/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * int crypto_generichash(unsigned char *out,
 *                        size_t outlen,
 *                        const unsigned char *in,
 *                        unsigned long long inlen,
 *                        const unsigned char *key,
 *                        size_t keylen);
 *  buffer out,
 *  number out_size,
 *  buffer in,
 *  buffer key
 */
NAPI_METHOD(crypto_generichash) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments must be: hash size, message, key");
    ARG_TO_NUMBER(out_size);
    ARG_TO_UCHAR_BUFFER(in);
    ARG_TO_UCHAR_BUFFER_OR_NULL(key);

    if (key != NULL) {
        CHECK_SIZE(key_size, crypto_generichash_KEYBYTES_MIN, crypto_generichash_KEYBYTES_MAX);
    }
    CHECK_SIZE(out_size, crypto_generichash_BYTES_MIN, crypto_generichash_BYTES_MAX);

    NEW_BUFFER_AND_PTR(hash, out_size);
    sodium_memzero(hash_ptr, out_size);

    if (crypto_generichash(hash_ptr, out_size, in, in_size, key, key_size) == 0) {
        return hash;
    }

    return NAPI_NULL;
}

/*
int crypto_generichash_init(crypto_generichash_state *state,
                            const unsigned char *key,
                            const size_t keylen, const size_t outlen);
  Buffer state
  Buffer key
  Number out_size
  state = sodium_malloc((crypto_generichash_statebytes() + (size_t) 63U)
 *                       & ~(size_t) 63U);
*/
NAPI_METHOD(crypto_generichash_init) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be: key buffer, output size");
    ARG_TO_UCHAR_BUFFER_OR_NULL(key);
    ARG_TO_NUMBER(out_size);

    if (key != NULL) {
        CHECK_SIZE(key_size, crypto_generichash_KEYBYTES_MIN, crypto_generichash_KEYBYTES_MAX);
    }
    CHECK_SIZE(out_size, crypto_generichash_BYTES_MIN, crypto_generichash_BYTES_MAX);

    NEW_BUFFER_AND_PTR(state, (crypto_generichash_statebytes() + (size_t) 63U) & ~(size_t) 63U);

    if (crypto_generichash_init((crypto_generichash_state *)state_ptr, key, key_size, out_size) == 0) {
        return state;
    }

    return NAPI_NULL;
}


/*
int crypto_generichash_update(crypto_generichash_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);

    buffer state
    buffer message
*/
NAPI_METHOD(crypto_generichash_update) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be: state buffer, message buffer");

    ARG_TO_UCHAR_BUFFER_LEN(state, crypto_generichash_statebytes()); //VOID
    ARG_TO_UCHAR_BUFFER(message);

    if (crypto_generichash_update((crypto_generichash_state *)state, message, message_size) == 0) {
        return NAPI_TRUE;
    }
    return NAPI_FALSE;
}

/*
int crypto_generichash_final(crypto_generichash_state *state,
                             unsigned char *out, const size_t outlen);
*/
NAPI_METHOD(crypto_generichash_final) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be: state buffer, output size");
    ARG_TO_UCHAR_BUFFER(state); // VOID
    ARG_TO_NUMBER(out_size); 

    CHECK_SIZE(out_size, crypto_generichash_BYTES_MIN, crypto_generichash_BYTES_MAX);
    NEW_BUFFER_AND_PTR(hash, out_size);

    if (crypto_generichash_final((crypto_generichash_state *)state, hash_ptr, out_size) == 0) {
        return hash;
    }

    return NAPI_NULL;
}

NAPI_METHOD_FROM_STRING(crypto_generichash_primitive)
NAPI_METHOD_FROM_INT(crypto_generichash_statebytes)
NAPI_METHOD_FROM_INT(crypto_generichash_bytes)
NAPI_METHOD_FROM_INT(crypto_generichash_bytes_min)
NAPI_METHOD_FROM_INT(crypto_generichash_bytes_max)
NAPI_METHOD_FROM_INT(crypto_generichash_keybytes)
NAPI_METHOD_FROM_INT(crypto_generichash_keybytes_min)
NAPI_METHOD_FROM_INT(crypto_generichash_keybytes_max)

NAPI_METHOD_KEYGEN(crypto_generichash)

/**
 * Register function calls in node binding
 */
void register_crypto_generichash(Napi::Env env, Napi::Object exports) {

     // Generic Hash
    EXPORT(crypto_generichash);
    EXPORT(crypto_generichash_init);
    EXPORT(crypto_generichash_update);
    EXPORT(crypto_generichash_final);
    EXPORT(crypto_generichash_keygen);

    EXPORT_STRING(crypto_generichash_PRIMITIVE);
    EXPORT(crypto_generichash_statebytes);
    EXPORT_INT(crypto_generichash_BYTES);
    EXPORT_INT(crypto_generichash_BYTES_MIN);
    EXPORT_INT(crypto_generichash_BYTES_MAX);
    EXPORT_INT(crypto_generichash_KEYBYTES);
    EXPORT_INT(crypto_generichash_KEYBYTES_MIN);
    EXPORT_INT(crypto_generichash_KEYBYTES_MAX);

    EXPORT(crypto_generichash_primitive);
    EXPORT(crypto_generichash_bytes);
    EXPORT(crypto_generichash_bytes_min);
    EXPORT(crypto_generichash_bytes_max);
    EXPORT(crypto_generichash_keybytes);
    EXPORT(crypto_generichash_keybytes_min);
    EXPORT(crypto_generichash_keybytes_max);
}

