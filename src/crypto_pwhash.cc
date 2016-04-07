/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * “int crypto_pwhash_scryptsalsa208sha256(unsigned char * const out,
                                       unsigned long long outlen,
                                       const char * const passwd,
                                       unsigned long long passwdlen,
                                       const unsigned char * const salt,
                                       unsigned long long opslimit,
                                       size_t memlimit);”

    number out length
    buffer passwd
    buffer salt
    number opslimit
    number memlimit
 */
NAN_METHOD(bind_crypto_pwhash_scryptsalsa208sha256) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(5,"arguments must be: output length, password buffer, salt buffer, oLimit, memLimit");
    
    GET_ARG_POSITIVE_NUMBER(0, out_size);
    GET_ARG_AS(1, passwd, char*);
    GET_ARG_AS_UCHAR_LEN(2, salt, crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    GET_ARG_POSITIVE_NUMBER(3, oppLimit);
    GET_ARG_POSITIVE_NUMBER(4, memLimit);
    
    NEW_BUFFER_AND_PTR(hash, out_size);
    
    if (crypto_pwhash_scryptsalsa208sha256(hash_ptr, out_size, passwd, passwd_size, salt, oppLimit, memLimit) == 0) {
        return info.GetReturnValue().Set(hash);
    } else {
        return info.GetReturnValue().Set(Nan::Null());
    } 
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
NAN_METHOD(bind_crypto_pwhash_scryptsalsa208sha256_ll) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(6,"arguments must be: password buffer, salt buffer, N, r, p");
    
    GET_ARG_AS(0, passwd, uint8_t*);
    GET_ARG_AS(1, salt, uint8_t*);
    GET_ARG_POSITIVE_NUMBER(2, N);
    GET_ARG_POSITIVE_NUMBER(3, r);
    GET_ARG_POSITIVE_NUMBER(4, p);
    GET_ARG_AS(5, out, uint8_t*);
    
    if (crypto_pwhash_scryptsalsa208sha256_ll(passwd, passwd_size, salt, salt_size, N, r, p, out, out_size) == 0) {
        return info.GetReturnValue().Set(Nan::True());
    } else {
        return info.GetReturnValue().Set(Nan::Null());
    } 
}

/**
  int crypto_pwhash_scryptsalsa208sha256_str(char out[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
                                           const char * const passwd,
                                           unsigned long long passwdlen,
                                           unsigned long long opslimit,
                                           size_t memlimit);
                                           
                                           
 */
NAN_METHOD(bind_crypto_pwhash_scryptsalsa208sha256_str) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments must be: password buffer, oLimit, memLimit");
    
    GET_ARG_AS(0, passwd, char*);
    GET_ARG_POSITIVE_NUMBER(1, oppLimit);
    GET_ARG_POSITIVE_NUMBER(2, memLimit);
    
    NEW_BUFFER_AND_PTR(hash, crypto_pwhash_scryptsalsa208sha256_STRBYTES);
    
    if (crypto_pwhash_scryptsalsa208sha256_str((char*)hash_ptr, passwd, passwd_size, oppLimit, memLimit) == 0) {
        return info.GetReturnValue().Set(hash);
    } else {
        return info.GetReturnValue().Set(Nan::Null());
    } 
}

/**
 * int crypto_pwhash_scryptsalsa208sha256_str_verify(const char str[crypto_pwhash_scryptsalsa208sha256_STRBYTES],
                                                  const char * const passwd,
                                                  unsigned long long passwdlen);
 */
NAN_METHOD(bind_crypto_pwhash_scryptsalsa208sha256_str_verify) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments must be: pwhash string, password");
    
    GET_ARG_AS_UCHAR_LEN(0, hash, crypto_pwhash_scryptsalsa208sha256_STRBYTES);
    GET_ARG_AS(1, passwd, char*);
    
    if (crypto_pwhash_scryptsalsa208sha256_str_verify((char*)hash, passwd, passwd_size) == 0) {
        return info.GetReturnValue().Set(Nan::True());
    } else {
        return info.GetReturnValue().Set(Nan::False());
    } 
}


/**
 * Register function calls in node binding
 */
void register_pwhash(Handle<Object> target) {
    
    // Methods
    NEW_METHOD(crypto_pwhash_scryptsalsa208sha256);
    NEW_METHOD(crypto_pwhash_scryptsalsa208sha256_ll);
    NEW_METHOD(crypto_pwhash_scryptsalsa208sha256_str);
    NEW_METHOD(crypto_pwhash_scryptsalsa208sha256_str_verify);
    
    // Properties
    NEW_NUMBER_PROP(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE);
    NEW_NUMBER_PROP(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
    NEW_NUMBER_PROP(crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE);
    NEW_NUMBER_PROP(crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);
    NEW_INT_PROP(crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
    NEW_INT_PROP(crypto_pwhash_scryptsalsa208sha256_STRBYTES);
    NEW_STRING_PROP(crypto_pwhash_scryptsalsa208sha256_STRPREFIX);
    NEW_NUMBER_PROP(crypto_pwhash_ALG_DEFAULT);
    NEW_NUMBER_PROP(crypto_pwhash_SALTBYTES);
    NEW_NUMBER_PROP(crypto_pwhash_STRBYTES);
    NEW_STRING_PROP(crypto_pwhash_STRPREFIX);
    NEW_NUMBER_PROP(crypto_pwhash_OPSLIMIT_INTERACTIVE);
    NEW_NUMBER_PROP(crypto_pwhash_MEMLIMIT_INTERACTIVE);
    NEW_NUMBER_PROP(crypto_pwhash_OPSLIMIT_MODERATE);
    NEW_NUMBER_PROP(crypto_pwhash_MEMLIMIT_MODERATE);
    NEW_NUMBER_PROP(crypto_pwhash_OPSLIMIT_SENSITIVE);
    NEW_NUMBER_PROP(crypto_pwhash_MEMLIMIT_SENSITIVE);   
}