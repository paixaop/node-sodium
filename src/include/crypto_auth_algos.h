/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __CRYPTO_AUTH_ALGOS_H__
#define __CRYPTO_AUTH_ALGOS_H__

#define CRYPTO_AUTH_DEF(ALGO) \
    NAPI_METHOD(crypto_auth_ ## ALGO) { \
         Napi::Env env = info.Env(); \
        ARGS(2, "arguments message, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER(msg);\
        ARG_TO_UCHAR_BUFFER(key); \
        NEW_BUFFER_AND_PTR(token, crypto_auth_ ## ALGO ## _BYTES); \
        if( crypto_auth_ ## ALGO (token_ptr, msg, msg_size, key) == 0 ) { \
            return token; \
        } \
        return NAPI_NULL; \
    }\
    NAPI_METHOD(crypto_auth_ ## ALGO ## _verify) { \
         Napi::Env env = info.Env(); \
        ARGS(3, "arguments token, message, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER_LEN(token, crypto_auth_ ## ALGO ## _BYTES); \
        ARG_TO_UCHAR_BUFFER(message); \
        ARG_TO_UCHAR_BUFFER(key); \
        return  \
            Napi::Number::New(env, crypto_auth_ ## ALGO ## _verify(token, message, message_size, key)) \
        ;\
    }\
    NAPI_METHOD(crypto_auth_ ## ALGO ## _init) { \
         Napi::Env env = info.Env(); \
        ARGS(1, "argument key must a buffer"); \
        ARG_TO_UCHAR_BUFFER(key); \
        NEW_BUFFER_AND_PTR(state, crypto_auth_ ## ALGO ## _statebytes()); \
        if( crypto_auth_ ## ALGO ## _init((crypto_auth_ ## ALGO ## _state*) state_ptr, key, key_size) == 0 ) { \
            return state; \
        } \
        return NAPI_NULL; \
    } \
    NAPI_METHOD(crypto_auth_ ## ALGO ## _update) { \
         Napi::Env env = info.Env(); \
        ARGS(2, "arguments must be two buffers: hash state, message part"); \
        ARG_TO_UCHAR_BUFFER_LEN(state, crypto_auth_ ## ALGO ## _statebytes()); /* VOID */\
        ARG_TO_UCHAR_BUFFER_OR_NULL(msg); \
        if( crypto_auth_ ## ALGO ## _update((crypto_auth_ ## ALGO ## _state*)state, msg, msg_size) == 0 ) { \
            return NAPI_TRUE;  \
        } \
        return NAPI_FALSE;  \
    } \
    NAPI_METHOD(crypto_auth_ ## ALGO ## _final) { \
        Napi::Env env = info.Env(); \
        ARGS(1, "arguments must be a hash state buffer"); \
        ARG_TO_UCHAR_BUFFER(state);  /* VOID */\
        NEW_BUFFER_AND_PTR(token, crypto_auth_ ## ALGO ## _BYTES); \
        if( crypto_auth_ ## ALGO ## _final((crypto_auth_ ## ALGO ## _state*)state, token_ptr) == 0 ) { \
            return token; \
        } \
        return NAPI_NULL; \
    } \
    NAPI_METHOD(crypto_auth_ ## ALGO ## _statebytes) { \
        Napi::Env env = info.Env(); \
        return Napi::Number::New(env, crypto_auth_ ## ALGO ## _statebytes()); \
    } \
    NAPI_METHOD(crypto_auth_ ## ALGO ## _keygen) { \
        NEW_BUFFER_AND_PTR(buffer, crypto_auth_ ## ALGO ## _KEYBYTES); \
        randombytes_buf(buffer_ptr, crypto_auth_ ## ALGO ## _KEYBYTES); \
        return buffer; \
    } \
    NAPI_METHOD_FROM_INT(crypto_auth_ ## ALGO ## _bytes) \
    NAPI_METHOD_FROM_INT(crypto_auth_ ## ALGO ## _keybytes)

#define METHOD_AND_PROPS(ALGO) \
    EXPORT(crypto_auth_ ## ALGO); \
    EXPORT(crypto_auth_ ## ALGO ## _verify); \
    EXPORT(crypto_auth_ ## ALGO ## _init); \
    EXPORT(crypto_auth_ ## ALGO ## _update); \
    EXPORT(crypto_auth_ ## ALGO ## _final); \
    EXPORT(crypto_auth_ ## ALGO ## _statebytes); \
    EXPORT(crypto_auth_ ## ALGO ## _keygen); \
    EXPORT(crypto_auth_ ## ALGO ## _bytes); \
    EXPORT(crypto_auth_ ## ALGO ## _keybytes); \
    EXPORT_INT(crypto_auth_ ## ALGO ## _BYTES); \
    EXPORT_INT(crypto_auth_ ## ALGO ## _KEYBYTES);

#define NAPI_PROTOTYPES(ALGO) \
    NAPI_METHOD(crypto_auth_ ## ALGO); \
    NAPI_METHOD(crypto_auth_ ## ALGO ## _verify); \
    NAPI_METHOD(crypto_auth_ ## ALGO ## _init); \
    NAPI_METHOD(crypto_auth_ ## ALGO ## _update); \
    NAPI_METHOD(crypto_auth_ ## ALGO ## _final); \
    NAPI_METHOD(crypto_auth_ ## ALGO ## _statebytes); \
    NAPI_METHOD(crypto_auth_ ## ALGO ## _keygen);

NAPI_PROTOTYPES(hmacsha256);
NAPI_PROTOTYPES(hmacsha512);
NAPI_PROTOTYPES(hmacsha512256);

#endif