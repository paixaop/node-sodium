/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __CRYPTO_CORE_H__
#define __CRYPTO_CORE_H__

#define CRYPTO_CORE_DEF(ALGO) \
    NAPI_METHOD(crypto_core_##ALGO) { \
        Napi::Env env = info.Env(); \
        ARGS(3, "arguments are: input buffer, key buffer, c constant buffer"); \
        ARG_TO_UCHAR_BUFFER_LEN(in, crypto_core_ ## ALGO ## _INPUTBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(key, crypto_core_ ## ALGO ## _KEYBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN_OR_NULL(c, crypto_core_ ## ALGO ## _CONSTBYTES); \
        NEW_BUFFER_AND_PTR(out, crypto_core_ ## ALGO ## _OUTPUTBYTES); \
        if (crypto_core_ ## ALGO (out_ptr, in, key, c) == 0) { \
            return out; \
        } \
        return NAPI_NULL; \
    } \
    NAPI_METHOD_FROM_INT(crypto_core_ ## ALGO ## _constbytes); \
    NAPI_METHOD_FROM_INT(crypto_core_ ## ALGO ## _inputbytes); \
    NAPI_METHOD_FROM_INT(crypto_core_ ## ALGO ## _keybytes); \
    NAPI_METHOD_FROM_INT(crypto_core_ ## ALGO ## _outputbytes)  


#define METHOD_AND_PROPS(ALGO) \
    EXPORT(crypto_core_ ## ALGO); \
    EXPORT(crypto_core_ ## ALGO ## _constbytes); \
    EXPORT(crypto_core_ ## ALGO ## _inputbytes); \
    EXPORT(crypto_core_ ## ALGO ## _keybytes); \
    EXPORT(crypto_core_ ## ALGO ## _outputbytes); \
    EXPORT_INT(crypto_core_ ## ALGO ## _CONSTBYTES); \
    EXPORT_INT(crypto_core_ ## ALGO ## _INPUTBYTES); \
    EXPORT_INT(crypto_core_ ## ALGO ## _KEYBYTES); \
    EXPORT_INT(crypto_core_ ## ALGO ## _OUTPUTBYTES)  

#endif