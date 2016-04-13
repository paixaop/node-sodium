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
    NAN_METHOD(bind_crypto_auth_ ## ALGO) { \
        Nan::EscapableHandleScope scope; \
        ARGS(2,"arguments message, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER(msg);\
        ARG_TO_UCHAR_BUFFER_LEN(key, crypto_auth_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(token, crypto_auth_ ## ALGO ## _BYTES); \
        if( crypto_auth_ ## ALGO (token_ptr, msg, msg_size, key) == 0 ) { \
            return info.GetReturnValue().Set(token); \
        } \
        return info.GetReturnValue().Set(Nan::Null()); \
    }\
    NAN_METHOD(bind_crypto_auth_ ## ALGO ## _verify) { \
        Nan::EscapableHandleScope scope; \
        ARGS(3,"arguments token, message, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER_LEN(token, crypto_auth_ ## ALGO ## _BYTES); \
        ARG_TO_UCHAR_BUFFER(message); \
        ARG_TO_UCHAR_BUFFER_LEN(key, crypto_auth_ ## ALGO ## _KEYBYTES); \
        return info.GetReturnValue().Set( \
            Nan::New<Integer>(crypto_auth_ ## ALGO ## _verify(token, message, message_size, key))\
        );\
    }\
    NAN_METHOD(bind_crypto_auth_ ## ALGO ## _init) { \
        Nan::EscapableHandleScope scope; \
        ARGS(1,"argument key must a buffer"); \
        ARG_TO_UCHAR_BUFFER(key); \
        NEW_BUFFER_AND_PTR(state, crypto_auth_ ## ALGO ## _statebytes()); \
        if( crypto_auth_ ## ALGO ## _init((crypto_auth_ ## ALGO ## _state*) state_ptr, key, key_size) == 0 ) { \
            return info.GetReturnValue().Set(state); \
        } \
        return info.GetReturnValue().Set(Nan::Null()); \
    } \
    NAN_METHOD(bind_crypto_auth_ ## ALGO ## _update) { \
        Nan::EscapableHandleScope scope; \
        ARGS(2,"arguments must be two buffers: hash state, message part"); \
        ARG_TO_VOID_BUFFER(state); \
        ARG_TO_UCHAR_BUFFER(msg); \
        if( crypto_auth_ ## ALGO ## _update((crypto_auth_ ## ALGO ## _state*)state, msg, msg_size) == 0 ) { \
            return info.GetReturnValue().Set(Nan::True()); \
        } \
        return info.GetReturnValue().Set(Nan::False()); \
    } \
    NAN_METHOD(bind_crypto_auth_ ## ALGO ## _final) { \
        Nan::EscapableHandleScope scope; \
        ARGS(1,"arguments must be a hash state buffer"); \
        ARG_TO_VOID_BUFFER(state); \
        NEW_BUFFER_AND_PTR(hash, crypto_auth_ ## ALGO ## _BYTES); \
        if( crypto_auth_ ## ALGO ## _final((crypto_auth_ ## ALGO ## _state*)state, hash_ptr) == 0 ) { \
            return info.GetReturnValue().Set(hash); \
        } \
        return info.GetReturnValue().Set(Nan::False()); \
    } \


#define METHOD_AND_PROPS(ALGO) \
    NEW_METHOD(crypto_auth_ ## ALGO); \
    NEW_METHOD(crypto_auth_ ## ALGO ## _verify); \
    NEW_INT_PROP(crypto_auth_ ## ALGO ## _BYTES); \
    NEW_INT_PROP(crypto_auth_ ## ALGO ## _KEYBYTES);

#define NAN_METHODS(ALGO) \
    NAN_METHOD(bind_crypto_auth_ ## ALGO); \
    NAN_METHOD(bind_crypto_auth_ ## ALGO ## _verify); \

NAN_METHODS(hmacsha256);
NAN_METHODS(hmacsha512);
NAN_METHODS(hmacsha512256);

#endif