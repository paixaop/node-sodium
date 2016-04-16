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
int crypto_aead_aes256gcm_encrypt(unsigned char *c,
                                  unsigned long long *clen_p,
                                  const unsigned char *m,
                                  unsigned long long mlen,
                                  const unsigned char *ad,
                                  unsigned long long adlen,
                                  const unsigned char *nsec,
                                  const unsigned char *npub,
                                  const unsigned char *k);

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
    NAN_METHOD(bind_crypto_aead_ ## ALGO ## _encrypt) { \
        Nan::EscapableHandleScope scope; \
        ARGS(4,"arguments message, additional data, nonce, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER(m); \
        ARG_TO_UCHAR_BUFFER_OR_NULL(ad); \
        ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_ ## ALGO ## _NPUBBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(k, crypto_aead_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(c, crypto_aead_ ## ALGO ## _ABYTES + m_size); \
        sodium_memzero(c_ptr, crypto_aead_ ## ALGO ## _ABYTES + m_size); \
        unsigned long long clen;\
        if( crypto_aead_ ## ALGO ## _encrypt (c_ptr, &clen, m, m_size, ad, ad_size, NULL, npub, k) == 0 ) { \
            return info.GetReturnValue().Set(c); \
        } \
        return info.GetReturnValue().Set(Nan::Undefined()); \
    } \
    NAN_METHOD(bind_crypto_aead_ ## ALGO ## _decrypt) { \
        Nan::EscapableHandleScope scope; \
        ARGS(4,"arguments chiper text, additional data, nonce, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER(c); \
        if( c_size < crypto_aead_ ## ALGO ## _ABYTES ) { \
            std::ostringstream oss; \
            oss << "argument cipher text must be at least " <<  crypto_aead_ ## ALGO ## _ABYTES << " bytes long" ; \
            return Nan::ThrowError(oss.str().c_str()); \
        } \
        ARG_TO_UCHAR_BUFFER_OR_NULL(ad); \
        ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_ ## ALGO ## _NPUBBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(k, crypto_aead_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(m, c_size - crypto_aead_ ## ALGO ## _ABYTES); \
        unsigned long long mlen;\
        if( crypto_aead_ ## ALGO ## _decrypt (m_ptr, &mlen, NULL, c, c_size, ad, ad_size, npub, k) == 0 ) { \
            return info.GetReturnValue().Set(m); \
        } \
        return info.GetReturnValue().Set(Nan::Undefined()); \
    }

#define CRYPTO_AEAD_DETACHED_DEF(ALGO) \
    NAN_METHOD(bind_crypto_aead_ ## ALGO ## _encrypt_detached) { \
        Nan::EscapableHandleScope scope; \
        ARGS(6,"arguments mac, message, additional data, nsec, nonce, and key must be buffers, nsec can be NULL"); \
        ARG_TO_UCHAR_BUFFER(mac); \
        ARG_TO_UCHAR_BUFFER(m); \
        ARG_TO_UCHAR_BUFFER_OR_NULL(ad); \
        ARG_TO_UCHAR_BUFFER_LEN_OR_NULL(nsec, crypto_aead_ ## ALGO ## _NSECBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_ ## ALGO ## _NPUBBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(k, crypto_aead_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(c, m_size); \
        if( crypto_aead_ ## ALGO ## _encrypt_detached (c_ptr, mac, &mac_size, m, m_size, ad, ad_size, nsec, npub, k) == 0 ) { \
            return info.GetReturnValue().Set(c); \
        } \
        return info.GetReturnValue().Set(Nan::Undefined()); \
    }\
    NAN_METHOD(bind_crypto_aead_ ## ALGO ## _decrypt_detached) { \
        Nan::EscapableHandleScope scope; \
        ARGS(6,"arguments cipher message, nsec, mac, additional data, nsec, nonce, and key must be buffers, nsec can be NULL"); \
        ARG_TO_UCHAR_BUFFER_LEN_OR_NULL(nsec, crypto_aead_ ## ALGO ## _NSECBYTES); \
        ARG_TO_UCHAR_BUFFER(c); \
        ARG_TO_UCHAR_BUFFER(mac); \
        ARG_TO_UCHAR_BUFFER_OR_NULL(ad); \
        ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_ ## ALGO ## _NPUBBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(k, crypto_aead_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(m, c_size); \
        if( crypto_aead_ ## ALGO ## _decrypt_detached (m_ptr, nsec, c, c_size, mac, ad, ad_size, npub, k) == 0 ) { \
            return info.GetReturnValue().Set(m); \
        } \
        return info.GetReturnValue().Set(Nan::Undefined()); \
    }

#define METHOD_AND_PROPS(ALGO) \
    NEW_METHOD(crypto_aead_ ## ALGO ## _decrypt); \
    NEW_METHOD(crypto_aead_ ## ALGO ## _decrypt_detached); \
    NEW_METHOD(crypto_aead_ ## ALGO ## _encrypt); \
    NEW_METHOD(crypto_aead_ ## ALGO ## _encrypt_detached); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _ABYTES); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _KEYBYTES); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _NPUBBYTES); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _NSECBYTES); 

#define NAN_METHODS(ALGO) \
    NAN_METHOD(bind_crypto_aead_ ## ALGO ## _decrypt); \
    NAN_METHOD(bind_crypto_aead_ ## ALGO ## _decrypt_detached); \
    NAN_METHOD(bind_crypto_aead_ ## ALGO ## _encrypt); \
    NAN_METHOD(bind_crypto_aead_ ## ALGO ## _encrypt_detached); \


#endif