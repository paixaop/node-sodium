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
    Napi::Value bind_crypto_aead_ ## ALGO ## _encrypt (const Napi::CallbackInfo& info) { \
        Napi::Env env = info.Env(); \
        ARGS(4,"arguments message, additional data, nonce, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER(m); \
        ARG_TO_UCHAR_BUFFER_OR_NULL(ad); \
        ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_ ## ALGO ## _NPUBBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(k, crypto_aead_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(c, crypto_aead_ ## ALGO ## _ABYTES + m_size); \
        sodium_memzero(c_ptr, crypto_aead_ ## ALGO ## _ABYTES + m_size); \
        unsigned long long clen;\
        if( crypto_aead_ ## ALGO ## _encrypt (c_ptr, &clen, m, m_size, ad, ad_size, NULL, npub, k) == 0 ) { \
            return c; \
        } \
        return env.Undefined(); \
    } \
    Napi::Value bind_crypto_aead_ ## ALGO ## _decrypt(const Napi::CallbackInfo& info) { \
        Napi::Env env = info.Env(); \
        ARGS(4,"arguments chiper text, additional data, nonce, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER(c); \
        if( c_size < crypto_aead_ ## ALGO ## _ABYTES ) { \
            std::ostringstream oss; \
            oss << "argument cipher text must be at least " <<  crypto_aead_ ## ALGO ## _ABYTES << " bytes long" ; \
            Napi::Error::New(env, oss.str().c_str()).ThrowAsJavaScriptException(); \
            return env.Null(); \
        } \
        ARG_TO_UCHAR_BUFFER_OR_NULL(ad); \
        ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_ ## ALGO ## _NPUBBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(k, crypto_aead_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(m, c_size - crypto_aead_ ## ALGO ## _ABYTES); \
        unsigned long long mlen;\
        if( crypto_aead_ ## ALGO ## _decrypt (m_ptr, &mlen, NULL, c, c_size, ad, ad_size, npub, k) == 0 ) { \
            return m; \
        } \
        return env.Undefined(); \
    } \
    Napi::Value bind_crypto_aead_ ## ALGO ## _keygen (const Napi::CallbackInfo& info) { \
        NEW_BUFFER_AND_PTR(buffer, crypto_aead_ ## ALGO ## _KEYBYTES); \
        crypto_aead_ ## ALGO ## _keygen(buffer_ptr); \
        return buffer; \
    }


/*
 SODIUM_EXPORT
int crypto_aead_aes256gcm_encrypt_detached(unsigned char *c,
                                           unsigned char *mac,
                                           unsigned long long *maclen_p,
                                           const unsigned char *m,
                                           unsigned long long mlen,
                                           const unsigned char *ad,
                                           unsigned long long adlen,
                                           const unsigned char *nsec,
                                           const unsigned char *npub,
                                           const unsigned char *k);

int crypto_aead_aes256gcm_decrypt_detached(unsigned char *m,
                                           unsigned char *nsec,
                                           const unsigned char *c,
                                           unsigned long long clen,
                                           const unsigned char *mac,
                                           const unsigned char *ad,
                                           unsigned long long adlen,
                                           const unsigned char *npub,
                                           const unsigned char *k)
*/
#define CRYPTO_AEAD_DETACHED_DEF(ALGO) \
    Napi::Value bind_crypto_aead_ ## ALGO ## _encrypt_detached(const Napi::CallbackInfo& info) { \
        Napi::Env env = info.Env(); \
        ARGS(4,"arguments message, additional data, nonce, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER(m); \
        ARG_TO_UCHAR_BUFFER_OR_NULL(ad); \
        ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_ ## ALGO ## _NPUBBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(k, crypto_aead_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(c, m_size); \
        NEW_BUFFER_AND_PTR(mac, crypto_aead_ ## ALGO ## _ABYTES); \
        unsigned long long maclen;\
        if( crypto_aead_ ## ALGO ## _encrypt_detached (c_ptr, mac_ptr, &maclen, m, m_size, ad, ad_size, NULL, npub, k) == 0 ) { \
            Napi::Object result = Napi::Object::New(env); \
            result.Set(Napi::String::New(env, "cipherText"), c); \
            result.Set(Napi::String::New(env, "mac"), mac); \
            return result; \
        } \
        return env.Undefined(); \
    }\
    Napi::Value bind_crypto_aead_ ## ALGO ## _decrypt_detached(const Napi::CallbackInfo& info) { \
        Napi::Env env = info.Env(); \
        ARGS(4,"arguments cipher message, mac, additional data, nsec, nonce, and key must be buffers"); \
        ARG_TO_UCHAR_BUFFER(c); \
        ARG_TO_UCHAR_BUFFER(mac); \
        ARG_TO_UCHAR_BUFFER_OR_NULL(ad); \
        if( mac_size > crypto_aead_ ## ALGO ## _ABYTES ) { \
            std::ostringstream oss; \
            oss << "argument mac cannot be longer than " <<  crypto_aead_ ## ALGO ## _ABYTES << " bytes" ; \
            Napi::Error::New(env, oss.str().c_str()).ThrowAsJavaScriptException(); \
            return env.Null(); \
        }\
        ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_ ## ALGO ## _NPUBBYTES); \
        ARG_TO_UCHAR_BUFFER_LEN(k, crypto_aead_ ## ALGO ## _KEYBYTES); \
        NEW_BUFFER_AND_PTR(m, c_size); \
        if( crypto_aead_ ## ALGO ## _decrypt_detached (m_ptr, NULL, c, c_size, mac, ad, ad_size, npub, k) == 0 ) { \
            return m; \
        } \
        return env.Undefined(); \
    }

#define METHOD_AND_PROPS(ALGO) \
    NEW_METHOD(crypto_aead_ ## ALGO ## _decrypt); \
    NEW_METHOD(crypto_aead_ ## ALGO ## _decrypt_detached); \
    NEW_METHOD(crypto_aead_ ## ALGO ## _encrypt); \
    NEW_METHOD(crypto_aead_ ## ALGO ## _keygen); \
    NEW_METHOD(crypto_aead_ ## ALGO ## _encrypt_detached); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _ABYTES); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _KEYBYTES); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _NPUBBYTES); \
    NEW_INT_PROP(crypto_aead_ ## ALGO ## _NSECBYTES); 

#define METHODS(ALGO) \
    Napi::SetMethod(bind_crypto_aead_ ## ALGO ## _decrypt); \
    Napi::SetMethod(bind_crypto_aead_ ## ALGO ## _decrypt_detached); \
    Napi::SetMethod(bind_crypto_aead_ ## ALGO ## _encrypt); \
    Napi::SetMethod(bind_crypto_aead_ ## ALGO ## _encrypt_detached); \


#endif