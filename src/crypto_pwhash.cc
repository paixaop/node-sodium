/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"


/*
    int crypto_pwhash(unsigned char * const out, unsigned long long outlen,
                  const char * const passwd, unsigned long long passwdlen,
                  const unsigned char * const salt,
                  unsigned long long opslimit, size_t memlimit, int alg)

    Buffer out
    Buffer password
    Buffer salt
    Number oppsLimit
    Number memLimit
    Number algorithm

*/
NAPI_METHOD(crypto_pwhash) {
    Napi::Env env = info.Env();

    ARGS(6, "arguments must be: output buffer length, password buffer, salt buffer, oLimit, memLimit, algorithm");

    ARG_TO_NUMBER(outLen);
    ARG_TO_BUFFER_TYPE(passwd, char);
    ARG_TO_UCHAR_BUFFER_LEN(salt, crypto_pwhash_SALTBYTES);
    ARG_TO_NUMBER(oppLimit);
    ARG_TO_NUMBER(memLimit);
    ARG_TO_NUMBER(alg);
    if( outLen <= 0 ) {
        THROW_ERROR("output buffer length must be bigger than 0.");
    }
    NEW_BUFFER_AND_PTR(out, outLen);
    if (crypto_pwhash(out_ptr, outLen, passwd, passwd_size, salt, oppLimit, memLimit, alg) == 0) {
        return out;
    }
    return NAPI_NULL;
}


/**
 * int crypto_pwhash_str(char out[crypto_pwhash_STRBYTES],
                      const char * const passwd, unsigned long long passwdlen,
                      unsigned long long opslimit, size_t memlimit)

    Buffer out
    Buffer passwd
    Number oppsLimit
    Number memLimit
*/
NAPI_METHOD(crypto_pwhash_str) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments must be: password buffer, oLimit, memLimit");

    ARG_TO_BUFFER_TYPE(passwd, char);
    ARG_TO_NUMBER(oppLimit);
    ARG_TO_NUMBER(memLimit);

    NEW_BUFFER_AND_PTR(out, crypto_pwhash_STRBYTES);

    if (crypto_pwhash_str((char*)out_ptr, passwd, passwd_size, oppLimit, memLimit) == 0) {
        return out;
    }

    return NAPI_NULL;
}

/**
 * int crypto_pwhash_str_verify(const char str[crypto_pwhash_STRBYTES],
                             const char * const passwd,
                             unsigned long long passwdlen)

    Buffer hash String
    Buffer password
 */
NAPI_METHOD(crypto_pwhash_str_verify) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be: pwhash string, password");

    ARG_TO_UCHAR_BUFFER_LEN(hash, crypto_pwhash_STRBYTES);
    ARG_TO_BUFFER_TYPE(passwd, char);

    if (crypto_pwhash_str_verify((char*)hash, passwd, passwd_size) == 0) {
        return NAPI_TRUE;
    }

    return NAPI_FALSE;
}

NAPI_METHOD(crypto_pwhash_str_needs_rehash) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be: pwhash hash, oLimit, memLimit");
    ARG_TO_UCHAR_BUFFER_LEN(hash, crypto_pwhash_STRBYTES);
    ARG_TO_NUMBER(oppLimit);
    ARG_TO_NUMBER(memLimit);
    
    if (crypto_pwhash_str_needs_rehash((char*)hash, oppLimit, memLimit) == 0) {
        return NAPI_TRUE;
    }
    return NAPI_FALSE;
}

/*
crypto_pwhash_str_alg(char out[crypto_pwhash_STRBYTES],
                      const char * const passwd, unsigned long long passwdlen,
                      unsigned long long opslimit, size_t memlimit, int alg)
*/
NAPI_METHOD(crypto_pwhash_str_alg) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments must be: password buffer, oLimit, memLimit, and algorithm");

    ARG_TO_BUFFER_TYPE(passwd, char);
    ARG_TO_NUMBER(oppLimit);
    ARG_TO_NUMBER(memLimit);
    ARG_TO_NUMBER(alg);

    NEW_BUFFER_AND_PTR(out, crypto_pwhash_STRBYTES);

    if (crypto_pwhash_str_alg((char*)out_ptr, passwd, passwd_size, oppLimit, memLimit, alg) == 0) {
        return out;
    }

    return NAPI_NULL;
}

NAPI_METHOD_FROM_INT(crypto_pwhash_bytes_max)
NAPI_METHOD_FROM_INT(crypto_pwhash_bytes_min)
NAPI_METHOD_FROM_INT(crypto_pwhash_opslimit_max)
NAPI_METHOD_FROM_INT(crypto_pwhash_opslimit_min)
NAPI_METHOD_FROM_INT(crypto_pwhash_opslimit_interactive)
NAPI_METHOD_FROM_INT(crypto_pwhash_opslimit_sensitive)
NAPI_METHOD_FROM_INT(crypto_pwhash_memlimit_max)
NAPI_METHOD_FROM_INT(crypto_pwhash_memlimit_min)
NAPI_METHOD_FROM_INT(crypto_pwhash_memlimit_interactive)
NAPI_METHOD_FROM_INT(crypto_pwhash_memlimit_sensitive)
NAPI_METHOD_FROM_INT(crypto_pwhash_passwd_max)
NAPI_METHOD_FROM_INT(crypto_pwhash_passwd_min)
NAPI_METHOD_FROM_INT(crypto_pwhash_saltbytes)
NAPI_METHOD_FROM_INT(crypto_pwhash_strbytes)

NAPI_METHOD_FROM_INT(crypto_pwhash_alg_default)
NAPI_METHOD_FROM_INT(crypto_pwhash_alg_argon2i13)
NAPI_METHOD_FROM_INT(crypto_pwhash_alg_argon2id13)

NAPI_METHOD_FROM_STRING(crypto_pwhash_strprefix)
NAPI_METHOD_FROM_STRING(crypto_pwhash_primitive)

/**
 * Register function calls in node binding
 */
void register_crypto_pwhash(Napi::Env env, Napi::Object exports) {

    // Methods
    EXPORT(crypto_pwhash);
    EXPORT(crypto_pwhash_str);
    EXPORT(crypto_pwhash_str_verify);
    EXPORT(crypto_pwhash_str_alg);
    EXPORT(crypto_pwhash_str_needs_rehash);

    EXPORT(crypto_pwhash_alg_default);
    EXPORT(crypto_pwhash_alg_argon2id13);
    EXPORT(crypto_pwhash_alg_argon2i13);
    EXPORT(crypto_pwhash_primitive);
    
    EXPORT(crypto_pwhash_bytes_max);
    EXPORT(crypto_pwhash_bytes_min);
    EXPORT(crypto_pwhash_opslimit_max);
    EXPORT(crypto_pwhash_opslimit_min);
    EXPORT(crypto_pwhash_opslimit_interactive);
    EXPORT(crypto_pwhash_opslimit_sensitive);
    EXPORT(crypto_pwhash_memlimit_max);
    EXPORT(crypto_pwhash_memlimit_min);
    EXPORT(crypto_pwhash_memlimit_interactive);
    EXPORT(crypto_pwhash_memlimit_sensitive);
    EXPORT(crypto_pwhash_passwd_max);
    EXPORT(crypto_pwhash_passwd_min);
    EXPORT(crypto_pwhash_saltbytes);
    EXPORT(crypto_pwhash_strbytes);
    EXPORT(crypto_pwhash_strprefix);

    EXPORT(crypto_pwhash_alg_default);
    EXPORT(crypto_pwhash_alg_argon2i13);
    EXPORT(crypto_pwhash_alg_argon2id13);

    EXPORT(crypto_pwhash_strprefix);
    EXPORT(crypto_pwhash_primitive);

    EXPORT_INT(crypto_pwhash_BYTES_MAX);
    EXPORT_INT(crypto_pwhash_BYTES_MIN);
    EXPORT_INT(crypto_pwhash_OPSLIMIT_MAX);
    EXPORT_INT(crypto_pwhash_OPSLIMIT_MIN);
    EXPORT_INT(crypto_pwhash_OPSLIMIT_INTERACTIVE);
    EXPORT_INT(crypto_pwhash_OPSLIMIT_SENSITIVE);
    EXPORT_INT(crypto_pwhash_MEMLIMIT_MAX);
    EXPORT_INT(crypto_pwhash_MEMLIMIT_MIN);
    EXPORT_INT(crypto_pwhash_MEMLIMIT_INTERACTIVE);
    EXPORT_INT(crypto_pwhash_MEMLIMIT_SENSITIVE);
    EXPORT_INT(crypto_pwhash_PASSWD_MAX);
    EXPORT_INT(crypto_pwhash_PASSWD_MIN);
    EXPORT_INT(crypto_pwhash_SALTBYTES);
    EXPORT_INT(crypto_pwhash_STRBYTES);
    EXPORT_INT(crypto_pwhash_ALG_DEFAULT);
    EXPORT_INT(crypto_pwhash_ALG_ARGON2I13);
    EXPORT_INT(crypto_pwhash_ALG_ARGON2ID13);

    EXPORT_STRING(crypto_pwhash_STRPREFIX);
    EXPORT_STRING(crypto_pwhash_PRIMITIVE);
}