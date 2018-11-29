/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __CRYPTO_STREAMS_H__
#define __CRYPTO_STREAMS_H__

#define CRYPTO_STREAM_DEF(ALGO) \
    NAPI_METHOD(crypto_stream_##ALGO) { \
        Napi::Env env = info.Env(); \
        ARGS(3, "argument length must be a positive number, arguments nonce, and key must be buffers"); \
        ARG_TO_NUMBER(slen); \
        ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_stream_ ## ALGO ## _NONCEBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(key, crypto_stream_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(stream, slen); \
        if (crypto_stream_ ## ALGO (stream_ptr, slen, nonce, key) == 0) { \
            return stream; \
        } \
        return NAPI_NULL; \
    } \
    NAPI_METHOD(crypto_stream_ ## ALGO ## _xor) { \
        Napi::Env env = info.Env(); \
        ARGS(3, "arguments message, nonce, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER(message); \
        ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_stream_ ## ALGO ## _NONCEBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(key, crypto_stream_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(ctxt, message_size); \
        if (crypto_stream_ ## ALGO ## _xor(ctxt_ptr, message, message_size, nonce, key) == 0) { \
            return ctxt; \
        } \
        return NAPI_NULL; \
    } \
    NAPI_METHOD_FROM_INT(crypto_stream_ ## ALGO ## _keybytes); \
    NAPI_METHOD_FROM_INT(crypto_stream_ ## ALGO ## _noncebytes)

#define CRYPTO_STREAM_DEF_IC(ALGO) \
    NAPI_METHOD(crypto_stream_ ## ALGO ## _xor_ic) { \
        Napi::Env env = info.Env(); \
        ARGS(4, "arguments message, nonce, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER(message); \
        ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_stream_ ## ALGO ## _NONCEBYTES); \
        ARG_TO_NUMBER(ic); \
        ARG_TO_UCHAR_BUFFER_LEN(key, crypto_stream_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(ctxt, message_size); \
        if (crypto_stream_ ## ALGO ## _xor_ic(ctxt_ptr, message, message_size, nonce, ic, key) == 0) { \
            return ctxt; \
        } \
        return NAPI_NULL; \
    } 


#define METHODS(ALGO) \
    EXPORT(crypto_stream_ ## ALGO); \
    EXPORT(crypto_stream_ ## ALGO ## _xor); \
    EXPORT(crypto_stream_ ## ALGO ## _keybytes); \
    EXPORT(crypto_stream_ ## ALGO ## _noncebytes)

#define PROPS(ALGO) \
    EXPORT_INT(crypto_stream_ ## ALGO ## _KEYBYTES); \
    EXPORT_INT(crypto_stream_ ## ALGO ## _NONCEBYTES)

#define NAPI_PROTOTYPES(ALGO) \
    NAPI_METHOD(crypto_stream_ ## ALGO); \
    NAPI_METHOD(crypto_stream_ ## ALGO ## _xor);


NAPI_PROTOTYPES(xsalsa20);
NAPI_PROTOTYPES(salsa20);
NAPI_PROTOTYPES(salsa208);
NAPI_PROTOTYPES(salsa2012);
NAPI_PROTOTYPES(chacha20);
NAPI_PROTOTYPES(chacha20_ietf);


#endif