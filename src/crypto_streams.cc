/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"
#include "crypto_streams.h"

// Generate the binding methods for each algorithm
CRYPTO_STREAM_DEF(aes128ctr)
CRYPTO_STREAM_DEF(salsa20)
CRYPTO_STREAM_DEF_IC(salsa20)
CRYPTO_STREAM_DEF(xsalsa20)
CRYPTO_STREAM_DEF_IC(xsalsa20)
CRYPTO_STREAM_DEF(salsa208)
CRYPTO_STREAM_DEF(salsa2012)
CRYPTO_STREAM_DEF(chacha20)
CRYPTO_STREAM_DEF_IC(chacha20)

// chacha_ietf uses the same key length as crypto_stream_chacha20_KEYBYTES
// Libsodium does not define it, lets define it here so we don't get compilation errors
// when expanding the macros
#define crypto_stream_chacha20_ietf_KEYBYTES   crypto_stream_chacha20_KEYBYTES
#define crypto_stream_chacha20_ietf_NONCEBYTES crypto_stream_chacha20_IETF_NONCEBYTES
CRYPTO_STREAM_DEF(chacha20_ietf)
CRYPTO_STREAM_DEF_IC(chacha20_ietf)

/*
 *  int crypto_stream_aes128ctr_beforenm(unsigned char *c, const unsigned char *k);
 */
NAN_METHOD(bind_crypto_stream_aes128ctr_beforenm) { 
    Nan::EscapableHandleScope scope;
    
    ARGS(1,"arguments key must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_stream_aes128ctr_KEYBYTES);
    
    NEW_BUFFER_AND_PTR(ctxt, crypto_stream_aes128ctr_BEFORENMBYTES);
    
    if (crypto_stream_aes128ctr_beforenm(ctxt_ptr, key) == 0) {
        return info.GetReturnValue().Set(ctxt);
    }
    
    return info.GetReturnValue().Set(Nan::Null());
}

/*
    int crypto_stream_aes128ctr_afternm(unsigned char *out, unsigned long long len,
                                  const unsigned char *nonce, const unsigned char *c);
*/
NAN_METHOD(bind_crypto_stream_aes128ctr_afternm) { 
    Nan::EscapableHandleScope scope;
    
    ARGS(3,"arguments are: output buffer, nonce, beforenm output buffer");
    ARG_TO_UCHAR_BUFFER(out);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_stream_aes128ctr_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(c, crypto_stream_aes128ctr_BEFORENMBYTES);
    
    if (crypto_stream_aes128ctr_afternm(out, out_size, nonce, c) == 0) {
        return info.GetReturnValue().Set(Nan::True());
    }
    
    return info.GetReturnValue().Set(Nan::False());
}

/*
    int crypto_stream_aes128ctr_xor_afternm(unsigned char *out, const unsigned char *in,
                                        unsigned long long len,
                                        const unsigned char *nonce,
                                        const unsigned char *c);

*/
NAN_METHOD(bind_crypto_stream_aes128ctr_xor_afternm) { 
    Nan::EscapableHandleScope scope;
    
    ARGS(3,"arguments are: output buffer, nonce, beforenm output buffer");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_stream_aes128ctr_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(c, crypto_stream_aes128ctr_BEFORENMBYTES);
    
    NEW_BUFFER_AND_PTR(out, message_size);
    
    if (crypto_stream_aes128ctr_xor_afternm(out_ptr, message, message_size, nonce, c) == 0) {
        return info.GetReturnValue().Set(out);
    }
    
    return info.GetReturnValue().Set(Nan::Null());
}


/**
 * Register function calls in node binding
 */
void register_crypto_streams(Handle<Object> target) {
    
    METHODS(xsalsa20);
    NEW_METHOD(crypto_stream_xsalsa20_xor_ic);
    PROPS(xsalsa20);
    
    METHODS(salsa20);
    NEW_METHOD(crypto_stream_salsa20_xor_ic);
    PROPS(salsa20);
    
    METHODS(salsa208);
    PROPS(salsa208);
    
    METHODS(salsa2012);
    PROPS(salsa2012);
    
    METHODS(chacha20);
    NEW_METHOD(crypto_stream_chacha20_xor_ic);
    PROPS(chacha20);
    
    METHODS(chacha20_ietf);
    NEW_METHOD(crypto_stream_chacha20_ietf_xor_ic);
    PROPS(chacha20_ietf);
    
    METHODS(aes128ctr);
    NEW_INT_PROP(crypto_stream_aes128ctr_BEFORENMBYTES);
    NEW_METHOD(crypto_stream_aes128ctr_beforenm);
    NEW_METHOD(crypto_stream_aes128ctr_afternm);
    NEW_METHOD(crypto_stream_aes128ctr_xor_afternm);
    PROPS(aes128ctr);
}