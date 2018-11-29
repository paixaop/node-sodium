/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * int crypto_onetimeauth_poly1305(
 *       unsigned char*  tok,
 *       const unsigned char * msg,
 *       unsigned long long mlen,
 *       const unsigned char * key)
 *
 * Parameters:
 *  [out] 	tok 	the generated authentication token.
 *  [in] 	msg 	the message to be authenticated.
 *  [in] 	mlen 	the length of msg.
 *  [in] 	key 	the key used to compute the token.
 */
NAPI_METHOD(crypto_onetimeauth_poly1305) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments message, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_onetimeauth_poly1305_KEYBYTES);

    NEW_BUFFER_AND_PTR(token, crypto_onetimeauth_poly1305_BYTES);

    if( crypto_onetimeauth_poly1305(token_ptr, message, message_size, key) == 0 ) {
        return token;
    }

    return NAPI_NULL;
}

/**
 * int crypto_onetimeauth_poly1305_verify(
 *       unsigned char*  tok,
 *       const unsigned char * msg,
 *       unsigned long long mlen,
 *       const unsigned char * key)
 *
 * Parameters:
 *  [out] 	tok 	the generated authentication token.
 *  [in] 	msg 	the message to be authenticated.
 *  [in] 	mlen 	the length of msg.
 *  [in] 	key 	the key used to compute the token.
 */
NAPI_METHOD(crypto_onetimeauth_poly1305_verify) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments token, message, and key must be buffers");
    ARG_TO_UCHAR_BUFFER_LEN(token, crypto_onetimeauth_poly1305_BYTES);
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_onetimeauth_poly1305_KEYBYTES);

    return 
        Napi::Number::New(env, crypto_onetimeauth_poly1305_verify(token, message, message_size, key))
    ;
}

/*
int crypto_onetimeauth_poly1305_init(crypto_onetimeauth_poly1305_state *state,
                                     const unsigned char *key);

    buffer key
    return state
*/
NAPI_METHOD(crypto_onetimeauth_poly1305_init) {
    Napi::Env env = info.Env();

    ARGS(1, "argument key must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_onetimeauth_poly1305_KEYBYTES);

    NEW_BUFFER_AND_PTR(state, sizeof(crypto_onetimeauth_poly1305_state));

    if (crypto_onetimeauth_poly1305_init((crypto_onetimeauth_poly1305_state *)state_ptr, key) == 0) {
        return state;
    }

    return NAPI_NULL;
}

/*
int crypto_onetimeauth_poly1305_update(crypto_onetimeauth_poly1305_state *state,
                                       const unsigned char *in,
                                       unsigned long long inlen);
*/
NAPI_METHOD(crypto_onetimeauth_poly1305_update) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be: state buffer, message buffer");

    ARG_TO_UCHAR_BUFFER_LEN(state, crypto_onetimeauth_poly1305_statebytes());
    ARG_TO_UCHAR_BUFFER(message);

    if( crypto_onetimeauth_poly1305_update((crypto_onetimeauth_poly1305_state*)state, message, message_size) == 0 ) {
            return NAPI_TRUE;
    }
    return NAPI_FALSE;
}

/*
int crypto_onetimeauth_poly1305_final(crypto_onetimeauth_poly1305_state *state,
                                      unsigned char *out);
*/
NAPI_METHOD(crypto_onetimeauth_poly1305_final) {
    Napi::Env env = info.Env();

    ARGS(1, "arguments must be: state buffer");
    ARG_TO_UCHAR_BUFFER(state); // VOID

    NEW_BUFFER_AND_PTR(out, crypto_onetimeauth_poly1305_BYTES);

    if (crypto_onetimeauth_poly1305_final((crypto_onetimeauth_poly1305_state *)state, out_ptr) == 0) {
        return out;
    }

    return NAPI_NULL;
}

NAPI_METHOD_FROM_INT(crypto_onetimeauth_poly1305_bytes)
NAPI_METHOD_FROM_INT(crypto_onetimeauth_poly1305_keybytes)
NAPI_METHOD_FROM_INT(crypto_onetimeauth_poly1305_statebytes)
NAPI_METHOD_KEYGEN(crypto_onetimeauth_poly1305)

/**
 * Register function calls in node binding
 */
void register_crypto_onetimeauth_poly1305(Napi::Env env, Napi::Object exports) {

    // One Time Auth
    EXPORT(crypto_onetimeauth_poly1305);
    EXPORT(crypto_onetimeauth_poly1305_verify);
    EXPORT(crypto_onetimeauth_poly1305_init);
    EXPORT(crypto_onetimeauth_poly1305_update);
    EXPORT(crypto_onetimeauth_poly1305_final);
    EXPORT(crypto_onetimeauth_poly1305_bytes);
    EXPORT(crypto_onetimeauth_poly1305_keybytes);
    EXPORT(crypto_onetimeauth_poly1305_keygen);
    EXPORT(crypto_onetimeauth_poly1305_statebytes);

    EXPORT_INT(crypto_onetimeauth_poly1305_BYTES);
    EXPORT_INT(crypto_onetimeauth_poly1305_KEYBYTES);
}