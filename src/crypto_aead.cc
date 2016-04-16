/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"
#include "crypto_aead.h"

NAN_METHOD(bind_crypto_aead_aes256gcm_is_available) {
    Nan::EscapableHandleScope scope;

    if( crypto_aead_aes256gcm_is_available() == 1 ) {
        return info.GetReturnValue().Set(Nan::True());
    }
    
    return info.GetReturnValue().Set(Nan::False());
}


/* int crypto_aead_aes256gcm_beforenm(crypto_aead_aes256gcm_state *ctx_,
                                   const unsigned char *k);
*/
NAN_METHOD(bind_crypto_aead_aes256gcm_beforenm) { 
    Nan::EscapableHandleScope scope;
    
    ARGS(1,"arguments key must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_aead_aes256gcm_KEYBYTES);
    
    NEW_BUFFER_AND_PTR(ctxt, crypto_aead_aes256gcm_statebytes());
    
    if (crypto_aead_aes256gcm_beforenm((crypto_aead_aes256gcm_state*)ctxt_ptr, key) == 0) {
        return info.GetReturnValue().Set(ctxt);
    }
    
    return info.GetReturnValue().Set(Nan::Undefined());
}

/*
 int crypto_aead_aes256gcm_encrypt_afternm(unsigned char *c,
                                          unsigned long long *clen_p,
                                          const unsigned char *m,
                                          unsigned long long mlen,
                                          const unsigned char *ad,
                                          unsigned long long adlen,
                                          const unsigned char *nsec,
                                          const unsigned char *npub,
                                          const crypto_aead_aes256gcm_state *ctx_);
*/
NAN_METHOD(bind_crypto_aead_aes256gcm_encrypt_afternm) {
    Nan::EscapableHandleScope scope;
    ARGS(4,"arguments message, additional data, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(m);
    ARG_TO_UCHAR_BUFFER_OR_NULL(ad);
    ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_aes256gcm_NPUBBYTES);
    ARG_TO_VOID_BUFFER_LEN(ctx, crypto_aead_aes256gcm_statebytes());
    NEW_BUFFER_AND_PTR(c, crypto_aead_aes256gcm_ABYTES + m_size);
    sodium_memzero(c_ptr, crypto_aead_aes256gcm_ABYTES + m_size);
    unsigned long long clen;
    if( crypto_aead_aes256gcm_encrypt_afternm (c_ptr, &clen, m, m_size, ad, ad_size, NULL, npub, (crypto_aead_aes256gcm_state*)ctx) == 0 ) {
        return info.GetReturnValue().Set(c);
    }
    return info.GetReturnValue().Set(Nan::Undefined());
}

/*
 int crypto_aead_aes256gcm_decrypt_afternm(unsigned char *m,
                                          unsigned long long *mlen_p,
                                          unsigned char *nsec,
                                          const unsigned char *c,
                                          unsigned long long clen,
                                          const unsigned char *ad,
                                          unsigned long long adlen,
                                          const unsigned char *npub,
                                          const crypto_aead_aes256gcm_state *ctx_)
*/
NAN_METHOD(bind_crypto_aead_aes256gcm_decrypt_afternm) {
    Nan::EscapableHandleScope scope;
    
    ARGS(4,"arguments chiper text, additional data, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(c);
    if( c_size < crypto_aead_aes256gcm_ABYTES ) {
        std::ostringstream oss;
        oss << "argument cipher text must be at least " <<  crypto_aead_aes256gcm_ABYTES << " bytes long" ;
        return Nan::ThrowError(oss.str().c_str());
    }
    ARG_TO_UCHAR_BUFFER_OR_NULL(ad);
    ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_aes256gcm_NPUBBYTES);
    ARG_TO_VOID_BUFFER_LEN(ctx, crypto_aead_aes256gcm_statebytes());
    
    NEW_BUFFER_AND_PTR(m, c_size - crypto_aead_aes256gcm_ABYTES);
    unsigned long long mlen;
    
    if( crypto_aead_aes256gcm_decrypt_afternm (m_ptr, &mlen, NULL, c, c_size, ad, ad_size, npub, (crypto_aead_aes256gcm_state*)ctx) == 0 ) {
        return info.GetReturnValue().Set(m);
    }
    
    return info.GetReturnValue().Set(Nan::Undefined());
}

/*
int crypto_aead_aes256gcm_encrypt_detached_afternm(unsigned char *c,
                                                   unsigned char *mac,
                                                   unsigned long long *maclen_p,
                                                   const unsigned char *m,
                                                   unsigned long long mlen,
                                                   const unsigned char *ad,
                                                   unsigned long long adlen,
                                                   const unsigned char *nsec,
                                                   const unsigned char *npub,
                                                   const crypto_aead_aes256gcm_state *ctx_);
                                                   */
NAN_METHOD(bind_crypto_aead_aes256gcm_encrypt_detached_afternm) {
    Nan::EscapableHandleScope scope;
    
    ARGS(4,"arguments message, additional data, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(m);
    ARG_TO_UCHAR_BUFFER_OR_NULL(ad);
    ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_aes256gcm_NPUBBYTES);
    ARG_TO_VOID_BUFFER_LEN(ctx, crypto_aead_aes256gcm_statebytes());
    
    NEW_BUFFER_AND_PTR(c, m_size);
    NEW_BUFFER_AND_PTR(mac, crypto_aead_aes256gcm_ABYTES);
    
    if( crypto_aead_aes256gcm_encrypt_detached_afternm(c_ptr, mac_ptr, NULL, m, m_size, ad, ad_size, NULL, npub, (crypto_aead_aes256gcm_state*)ctx) == 0 ) {
        Local<Object> result = Nan::New<Object>();
        result->ForceSet(Nan::New<String>("cipherText").ToLocalChecked(), c, DontDelete);
        result->ForceSet(Nan::New<String>("mac").ToLocalChecked(), mac, DontDelete);
        return info.GetReturnValue().Set(result);
    }
    
    return info.GetReturnValue().Set(Nan::Undefined());
}

/*
int crypto_aead_aes256gcm_decrypt_detached_afternm(unsigned char *m,
                                                   unsigned char *nsec,
                                                   const unsigned char *c,
                                                   unsigned long long clen,
                                                   const unsigned char *mac,
                                                   const unsigned char *ad,
                                                   unsigned long long adlen,
                                                   const unsigned char *npub,
                                                   const crypto_aead_aes256gcm_state *ctx_)
*/
NAN_METHOD(bind_crypto_aead_aes256gcm_decrypt_detached_afternm) {
    Nan::EscapableHandleScope scope;
    
    ARGS(4,"arguments cipher message, mac, additional data, nsec, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(c);
    ARG_TO_UCHAR_BUFFER_LEN(mac, crypto_aead_aes256gcm_ABYTES);
    ARG_TO_UCHAR_BUFFER_OR_NULL(ad);
    ARG_TO_UCHAR_BUFFER_LEN(npub, crypto_aead_aes256gcm_NPUBBYTES);
    ARG_TO_VOID_BUFFER_LEN(ctx, crypto_aead_aes256gcm_statebytes());
    
    NEW_BUFFER_AND_PTR(m, c_size);
    
    if( crypto_aead_aes256gcm_decrypt_detached_afternm(m_ptr, NULL, c, c_size, mac, ad, ad_size, npub, (crypto_aead_aes256gcm_state*)ctx) == 0 ) {
        return info.GetReturnValue().Set(m);
    }
    
    return info.GetReturnValue().Set(Nan::Undefined());
}

CRYPTO_AEAD_DEF(aes256gcm)
CRYPTO_AEAD_DETACHED_DEF(aes256gcm)

CRYPTO_AEAD_DEF(chacha20poly1305)
CRYPTO_AEAD_DETACHED_DEF(chacha20poly1305)

CRYPTO_AEAD_DEF(chacha20poly1305_ietf)
CRYPTO_AEAD_DETACHED_DEF(chacha20poly1305_ietf)

/**
 * Register function calls in node binding
 */
void register_crypto_aead(Handle<Object> target) {
    NEW_METHOD(crypto_aead_aes256gcm_is_available);
    NEW_METHOD(crypto_aead_aes256gcm_beforenm);
    NEW_METHOD(crypto_aead_aes256gcm_encrypt_afternm);
    NEW_METHOD(crypto_aead_aes256gcm_decrypt_afternm);
    NEW_METHOD(crypto_aead_aes256gcm_encrypt_detached_afternm);
    NEW_METHOD(crypto_aead_aes256gcm_decrypt_detached_afternm);
    METHOD_AND_PROPS(aes256gcm);
    METHOD_AND_PROPS(chacha20poly1305);
    METHOD_AND_PROPS(chacha20poly1305_ietf);
}