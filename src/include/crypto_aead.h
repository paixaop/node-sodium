/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __CRYPTO_AEAD_H__
#define __CRYPTO_AEAD_H__

/*
int crypto_aead_aes256gcm_decrypt(unsigned char *m,
                                  unsigned long long *mlen_p,
                                  unsigned char *nsec,
                                  const unsigned char *c,
                                  unsigned long long clen,
                                  const unsigned char *ad,
                                  unsigned long long adlen,
                                  const unsigned char *npub,
                                  const unsigned char *k)
*/

#define CRYPTO_AEAD_DEF(ALGO) \
    NAN_METHOD(bind_crypto_aead_ ## ALGO ## _decrypt) { \
        Nan::EscapableHandleScope scope; \
        ARGS(2,"arguments message, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER(msg);\
        ARG_TO_UCHAR_BUFFER_LEN(key, crypto_auth_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(token, crypto_auth_ ## ALGO ## _BYTES); \
        if( crypto_auth_ ## ALGO ## _decrypt (token_ptr, msg, msg_size, key) == 0 ) { \
            return info.GetReturnValue().Set(token); \
        } \
        return info.GetReturnValue().Set(Nan::Null()); \
    }\  

#define METHOD_AND_PROPS(ALGO) \
    NEW_METHOD(crypto_aead_ ## ALGO ## _decrypt); \
    NEW_METHOD(crypto_aead_ ## ALGO ## _decrypt_detached); \
    NEW_METHOD(crypto_aead_ ## ALGO ## _encrypt); \
    NEW_METHOD(crypto_aead_ ## ALGO ## _encrypt_detached); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _ABYTES); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _KEYBYTES); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _NPUBBYTES); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _NSECBYTES); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _STATEBYTES);

#define NAN_METHODS(ALGO) \
    NAN_METHOD(bind_crypto_auth_ ## ALGO); \
    NAN_METHOD(bind_crypto_auth_ ## ALGO ## _verify); \


#endif