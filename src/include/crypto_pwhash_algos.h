/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __CRYPTO_PWHASH_ALGOS_H__
#define __CRYPTO_PWHASH_ALGOS_H__

#define CRYPTO_PWHASH_DEF(ALGO) \
    NAPI_METHOD(crypto_pwhash_ ## ALGO) { \
        Napi::Env env = info.Env(); \
        ARGS(5, "arguments must be: output buffer, password buffer, salt buffer, oLimit, memLimit"); \
        ARG_TO_NUMBER(outLen); \
        ARG_TO_BUFFER_TYPE(passwd, char); \
        ARG_TO_UCHAR_BUFFER_LEN(salt, crypto_pwhash_ ## ALGO ## _SALTBYTES); \
        ARG_TO_NUMBER(oppLimit); \
        ARG_TO_NUMBER(memLimit); \
        if( outLen <= 0 ) { \
            THROW_ERROR("output buffer length must be bigger than 0."); \
        } \
        if( passwd_size < crypto_pwhash_ ## ALGO ## _PASSWD_MIN ||  \
            passwd_size > crypto_pwhash_ ## ALGO ## _PASSWD_MAX ) {  \
            THROW_ERROR("password length should be at least sodium.crypto_pwhash_ ## ALGO ## _PASSWD_MIN " \
                        "and at most sodium.crypto_pwhash_ ## ALGO ## _PASSWD_MAX."); \
        } \
        NEW_BUFFER_AND_PTR(out, outLen); \
        if (crypto_pwhash_ ## ALGO (out_ptr, outLen, passwd, passwd_size, salt, oppLimit, memLimit) == 0) { \
            return out; \
        } \
        return NAPI_NULL; \
    }

#define CRYPTO_PWHASH_DEF_EXT(ALGO) \
    NAPI_METHOD(crypto_pwhash_ ## ALGO) { \
        Napi::Env env = info.Env(); \
        ARGS(6, "arguments must be: output buffer, password buffer, salt buffer, oLimit, memLimit"); \
        ARG_TO_NUMBER(outLen); \
        ARG_TO_BUFFER_TYPE(passwd, char); \
        ARG_TO_UCHAR_BUFFER_LEN(salt, crypto_pwhash_ ## ALGO ## _SALTBYTES); \
        ARG_TO_NUMBER(oppLimit); \
        ARG_TO_NUMBER(memLimit); \
        ARG_TO_NUMBER(alg); \
        if( outLen <= 0 ) { \
            THROW_ERROR("output buffer length must be bigger than 0."); \
        } \
        NEW_BUFFER_AND_PTR(out, outLen); \
        if (crypto_pwhash_ ## ALGO (out_ptr, outLen, passwd, passwd_size, salt, oppLimit, memLimit, alg) == 0) { \
            return out; \
        } \
        return NAPI_NULL; \
    }


#define CRYPTO_PWHASH_DEF_STR(ALGO) \
    NAPI_METHOD(crypto_pwhash_ ## ALGO ## _str) { \
        Napi::Env env = info.Env(); \
        ARGS(3, "arguments must be: password buffer, oLimit, memLimit"); \
        ARG_TO_BUFFER_TYPE(passwd, char); \
        ARG_TO_NUMBER(oppLimit); \
        ARG_TO_NUMBER(memLimit); \
        NEW_BUFFER_AND_PTR(out, crypto_pwhash_ ## ALGO ## _STRBYTES); \
        if( crypto_pwhash_ ## ALGO ## _str ((char*)out_ptr, passwd, passwd_size, oppLimit, memLimit) == 0 ) { \
            return out; \
        } \
        return NAPI_NULL; \
    } \
    NAPI_METHOD(crypto_pwhash_ ## ALGO ## _str_verify) { \
        Napi::Env env = info.Env(); \
        ARGS(2, "arguments must be: pwhash string, password"); \
        ARG_TO_UCHAR_BUFFER_LEN(hash, crypto_pwhash_ ## ALGO ## _STRBYTES); \
        ARG_TO_BUFFER_TYPE(passwd, char); \
        if (crypto_pwhash_ ## ALGO ## _str_verify((char*)hash, passwd, passwd_size) == 0) { \
            return NAPI_TRUE; \
        } \
        return NAPI_FALSE; \
    } \
    NAPI_METHOD(crypto_pwhash_ ## ALGO ## _str_needs_rehash) { \
        Napi::Env env = info.Env(); \
        ARGS(2, "arguments must be: pwhash hash, oLimit, memLimit"); \
        ARG_TO_UCHAR_BUFFER_LEN(hash, crypto_pwhash_ ## ALGO ## _STRBYTES); \
        ARG_TO_NUMBER(oppLimit); \
        ARG_TO_NUMBER(memLimit); \
        if (crypto_pwhash_ ## ALGO ## _str_needs_rehash((char*)hash, oppLimit, memLimit) == 0) { \
            return NAPI_TRUE; \
        } \
        return NAPI_FALSE; \
    } \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _bytes_max) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _bytes_min) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _opslimit_max) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _opslimit_min) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _opslimit_interactive) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _opslimit_sensitive) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _memlimit_max) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _memlimit_min) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _memlimit_interactive) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _memlimit_sensitive) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _passwd_max) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _passwd_min) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _saltbytes) \
    NAPI_METHOD_FROM_INT(crypto_pwhash_ ## ALGO ## _strbytes) \
    NAPI_METHOD_FROM_STRING(crypto_pwhash_ ## ALGO ## _strprefix)

#define CRYPTO_PWHASH_DEF_LL(ALGO) \
    NAPI_METHOD(crypto_pwhash_ ## ALGO ## _ll) { \
        Napi::Env env = info.Env(); \
        ARGS(6, "arguments must be: password buffer, salt buffer, N, r, p, output buffer"); \
        ARG_TO_BUFFER_TYPE(passwd, uint8_t); \
        ARG_TO_BUFFER_TYPE(salt, uint8_t); \
        ARG_TO_NUMBER(N); \
        ARG_TO_NUMBER(r); \
        ARG_TO_NUMBER(p); \
        ARG_TO_BUFFER_TYPE(out, uint8_t); \
        if (crypto_pwhash_ ## ALGO ## _ll(passwd, passwd_size, salt, salt_size, N, r, p, out, out_size) == 0) { \
            return NAPI_TRUE; \
        } \
        return NAPI_FALSE; \
    }

    

#define METHOD_AND_PROPS(ALGO) \
    EXPORT(crypto_pwhash_ ## ALGO); \
    EXPORT(crypto_pwhash_ ## ALGO ## _str); \
    EXPORT(crypto_pwhash_ ## ALGO ## _str_verify); \
    EXPORT(crypto_pwhash_ ## ALGO ## _str_needs_rehash); \
    EXPORT(crypto_pwhash_ ## ALGO ## _bytes_max); \
    EXPORT(crypto_pwhash_ ## ALGO ## _bytes_min); \
    EXPORT(crypto_pwhash_ ## ALGO ## _opslimit_max); \
    EXPORT(crypto_pwhash_ ## ALGO ## _opslimit_min); \
    EXPORT(crypto_pwhash_ ## ALGO ## _opslimit_interactive); \
    EXPORT(crypto_pwhash_ ## ALGO ## _opslimit_sensitive); \
    EXPORT(crypto_pwhash_ ## ALGO ## _memlimit_max); \
    EXPORT(crypto_pwhash_ ## ALGO ## _memlimit_min); \
    EXPORT(crypto_pwhash_ ## ALGO ## _memlimit_interactive); \
    EXPORT(crypto_pwhash_ ## ALGO ## _memlimit_sensitive); \
    EXPORT(crypto_pwhash_ ## ALGO ## _passwd_max); \
    EXPORT(crypto_pwhash_ ## ALGO ## _passwd_min); \
    EXPORT(crypto_pwhash_ ## ALGO ## _saltbytes); \
    EXPORT(crypto_pwhash_ ## ALGO ## _strbytes); \
    EXPORT(crypto_pwhash_ ## ALGO ## _strprefix); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _BYTES_MAX); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _BYTES_MIN); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _OPSLIMIT_MAX); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _OPSLIMIT_MIN); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _OPSLIMIT_INTERACTIVE); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _OPSLIMIT_SENSITIVE); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _MEMLIMIT_MAX); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _MEMLIMIT_MIN); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _MEMLIMIT_INTERACTIVE); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _MEMLIMIT_SENSITIVE); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _PASSWD_MAX); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _PASSWD_MIN); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _SALTBYTES); \
    EXPORT_INT(crypto_pwhash_ ## ALGO ## _STRBYTES); \
    EXPORT_STRING(crypto_pwhash_ ## ALGO ## _STRPREFIX);

#endif