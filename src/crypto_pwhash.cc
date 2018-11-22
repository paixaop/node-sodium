/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/* int crypto_pwhash_argon2i(unsigned char * const out,
                          unsigned long long outlen,
                          const char * const passwd,
                          unsigned long long passwdlen,
                          const unsigned char * const salt,
                          unsigned long long opslimit, size_t memlimit,
                          int alg)
*/
NAPI_METHOD(crypto_pwhash_argon2i) {
    Napi::Env env = info.Env();

    ARGS(6,"arguments must be: output buffer, password buffer, salt buffer, oLimit, memLimit, algorithm");

    ARG_TO_UCHAR_BUFFER(out);
    ARG_TO_BUFFER_TYPE(passwd, char);
    ARG_TO_UCHAR_BUFFER_LEN(salt, crypto_pwhash_argon2i_SALTBYTES);
    ARG_TO_NUMBER(oppLimit);
    ARG_TO_NUMBER(memLimit);
    ARG_TO_NUMBER(alg);

    if (crypto_pwhash_argon2i(out, out_size, passwd, passwd_size, salt, oppLimit, memLimit, alg) == 0) {
        return Napi::Boolean::New(env, true);
    }

    return env.Null();
}

/* int crypto_pwhash_argon2i_str(char out[crypto_pwhash_argon2i_STRBYTES],
                              const char * const passwd,
                              unsigned long long passwdlen,
                              unsigned long long opslimit, size_t memlimit)
*/
NAPI_METHOD(crypto_pwhash_argon2i_str) {
    Napi::Env env = info.Env();

    ARGS(3,"arguments must be: password buffer, oLimit, memLimit");

    ARG_TO_BUFFER_TYPE(passwd, char);
    ARG_TO_NUMBER(oppLimit);
    ARG_TO_NUMBER(memLimit);

    NEW_BUFFER_AND_PTR(buf, crypto_pwhash_argon2i_STRBYTES);
    buf_ptr++; 
    char *out_ptr = (char *) buf.Data();

    if (crypto_pwhash_argon2i_str(out_ptr, passwd, passwd_size, oppLimit, memLimit) == 0) {
        return buf;
    }

    return Napi::Boolean::New(env, false);
}

/* int crypto_pwhash_argon2i_str_verify(const char str[crypto_pwhash_argon2i_STRBYTES],
                                     const char * const passwd,
                                     unsigned long long passwdlen)
*/
NAPI_METHOD(crypto_pwhash_argon2i_str_verify) {
    Napi::Env env = info.Env();

    ARGS(2,"arguments must be: pwhash string, password");

    ARG_TO_BUFFER_TYPE(hash, char);
    ARG_TO_BUFFER_TYPE(passwd, char);

    if (crypto_pwhash_argon2i_str_verify(hash, passwd, passwd_size) == 0) {
        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}

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

    ARGS(6,"arguments must be: output buffer, password buffer, salt buffer, oLimit, memLimit, algorithm");

    ARG_TO_BUFFER_TYPE(out, unsigned char);
    ARG_TO_BUFFER_TYPE(passwd, char);
    ARG_TO_UCHAR_BUFFER_LEN(salt, crypto_pwhash_SALTBYTES);
    ARG_TO_NUMBER(oppLimit);
    ARG_TO_NUMBER(memLimit);
    ARG_TO_NUMBER(alg);

    if (crypto_pwhash(out, out_size, passwd, passwd_size, salt, oppLimit, memLimit, alg) == 0) {
        return Napi::Boolean::New(env, true);
    }

    return env.Null();
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

    ARGS(3,"arguments must be: password buffer, oLimit, memLimit");

    ARG_TO_BUFFER_TYPE(passwd, char);
    ARG_TO_NUMBER(oppLimit);
    ARG_TO_NUMBER(memLimit);

    NEW_BUFFER_AND_PTR(out, crypto_pwhash_STRBYTES);

    if (crypto_pwhash_str((char*)out_ptr, passwd, passwd_size, oppLimit, memLimit) == 0) {
        return out;
    }

    return Napi::Boolean::New(env, false);
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

    ARGS(2,"arguments must be: pwhash string, password");

    ARG_TO_UCHAR_BUFFER_LEN(hash, crypto_pwhash_STRBYTES);
    ARG_TO_BUFFER_TYPE(passwd, char);

    if (crypto_pwhash_str_verify((char*)hash, passwd, passwd_size) == 0) {
        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}


/**
 * int crypto_pwhash_scryptsalsa208sha256(unsigned char * const out,
                                       unsigned long long outlen,
                                       const char * const passwd,
                                       unsigned long long passwdlen,
                                       const unsigned char * const salt,
                                       unsigned long long opslimit,
                                       size_t memlimit);

    number out length
    buffer passwd
    buffer salt
    number opslimit
    number memlimit
 */
NAPI_METHOD(crypto_pwhash_scryptsalsa208sha256) {
    Napi::Env env = info.Env();

    ARGS(5,"arguments must be: output buffer, password buffer, salt buffer, oLimit, memLimit");

    ARG_TO_UCHAR_BUFFER(out);
    ARG_TO_BUFFER_TYPE(passwd, char);
    ARG_TO_UCHAR_BUFFER_LEN(salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    ARG_TO_NUMBER(oppLimit);
    ARG_TO_NUMBER(memLimit);

    if (crypto_pwhash_scryptsalsa208sha256(out, out_size, passwd, passwd_size, salt, oppLimit, memLimit) == 0) {
        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}

/**
 * int crypto_pwhash_scryptsalsa208sha256_ll(const uint8_t * passwd, size_t passwdlen,
                                          const uint8_t * salt, size_t saltlen,
                                          uint64_t N, uint32_t r, uint32_t p,
                                          uint8_t * buf, size_t buflen);
 * Buffer passwd
 * Buffer salt
 * Number N
 * Number r
 * Number p
 * Buffer scrypt hash output
 */
NAPI_METHOD(crypto_pwhash_scryptsalsa208sha256_ll) {
    Napi::Env env = info.Env();

    ARGS(6,"arguments must be: password buffer, salt buffer, N, r, p, output buffer");

    ARG_TO_BUFFER_TYPE(passwd, uint8_t);
    ARG_TO_BUFFER_TYPE(salt, uint8_t);
    ARG_TO_NUMBER(N);
    ARG_TO_NUMBER(r);
    ARG_TO_NUMBER(p);
    ARG_TO_BUFFER_TYPE(out, uint8_t);

    if (crypto_pwhash_scryptsalsa208sha256_ll(passwd, passwd_size, salt, salt_size, N, r, p, out, out_size) == 0) {
        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}

/**
  int crypto_pwhash_scryptsalsa208sha256_str(char out[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
                                           const char * const passwd,
                                           unsigned long long passwdlen,
                                           unsigned long long opslimit,
                                           size_t memlimit);


 */
NAPI_METHOD(crypto_pwhash_scryptsalsa208sha256_str) {
    Napi::Env env = info.Env();

    ARGS(3,"arguments must be: password buffer, oLimit, memLimit");

    ARG_TO_BUFFER_TYPE(passwd, char);
    ARG_TO_NUMBER(oppLimit);
    ARG_TO_NUMBER(memLimit);

    NEW_BUFFER_AND_PTR(hash, crypto_pwhash_scryptsalsa208sha256_STRBYTES);

    if (crypto_pwhash_scryptsalsa208sha256_str((char*)hash_ptr, passwd, passwd_size, oppLimit, memLimit) == 0) {
        return hash;
    }

    return env.Null();
}

/**
 * int crypto_pwhash_scryptsalsa208sha256_str_verify(const char str[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
                                                  const char * const passwd,
                                                  unsigned long long passwdlen);
 */
NAPI_METHOD(crypto_pwhash_scryptsalsa208sha256_str_verify) {
    Napi::Env env = info.Env();

    ARGS(2,"arguments must be: pwhash string, password");

    ARG_TO_UCHAR_BUFFER_LEN(hash, crypto_pwhash_scryptsalsa208sha256_STRBYTES);
    ARG_TO_BUFFER_TYPE(passwd, char);

    if (crypto_pwhash_scryptsalsa208sha256_str_verify((char*)hash, passwd, passwd_size) == 0) {
        return Napi::Boolean::New(env, true);
    }

    return Napi::Boolean::New(env, false);
}


/**
 * Register function calls in node binding
 */
void register_crypto_pwhash(Napi::Env env, Napi::Object exports) {

    // Methods
    EXPORT(crypto_pwhash);
    EXPORT(crypto_pwhash_str);
    EXPORT(crypto_pwhash_str_verify);
    EXPORT(crypto_pwhash_scryptsalsa208sha256);
    EXPORT(crypto_pwhash_scryptsalsa208sha256_ll);
    EXPORT(crypto_pwhash_scryptsalsa208sha256_str);
    EXPORT(crypto_pwhash_scryptsalsa208sha256_str_verify);
    EXPORT(crypto_pwhash_argon2i);
    EXPORT(crypto_pwhash_argon2i_str);
    EXPORT(crypto_pwhash_argon2i_str_verify);

    // Properties
    EXPORT_INT(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE);
    EXPORT_INT(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
    EXPORT_INT(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE);
    EXPORT_INT(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);
    EXPORT_INT(crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    EXPORT_INT(crypto_pwhash_scryptsalsa208sha256_STRBYTES);
    EXPORT_STRING(crypto_pwhash_scryptsalsa208sha256_STRPREFIX);

    EXPORT_INT(crypto_pwhash_ALG_DEFAULT);
    EXPORT_INT(crypto_pwhash_SALTBYTES);
    EXPORT_INT(crypto_pwhash_STRBYTES);
    EXPORT_STRING(crypto_pwhash_STRPREFIX);
    EXPORT_INT(crypto_pwhash_OPSLIMIT_INTERACTIVE);
    EXPORT_INT(crypto_pwhash_MEMLIMIT_INTERACTIVE);
    EXPORT_INT(crypto_pwhash_OPSLIMIT_MODERATE);
    EXPORT_INT(crypto_pwhash_MEMLIMIT_MODERATE);
    EXPORT_INT(crypto_pwhash_OPSLIMIT_SENSITIVE);
    EXPORT_INT(crypto_pwhash_MEMLIMIT_SENSITIVE);
    EXPORT_STRING(crypto_pwhash_PRIMITIVE);

    EXPORT_INT(crypto_pwhash_argon2i_ALG_ARGON2I13);
    EXPORT_INT(crypto_pwhash_argon2i_SALTBYTES);
    EXPORT_INT(crypto_pwhash_argon2i_STRBYTES);
    EXPORT_STRING(crypto_pwhash_argon2i_STRPREFIX);
    EXPORT_INT(crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE);
    EXPORT_INT(crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE);
    EXPORT_INT(crypto_pwhash_argon2i_OPSLIMIT_MODERATE);
    EXPORT_INT(crypto_pwhash_argon2i_MEMLIMIT_MODERATE);
    EXPORT_INT(crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE);
    EXPORT_INT(crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE);
}
