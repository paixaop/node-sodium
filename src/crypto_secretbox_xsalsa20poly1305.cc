/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

Napi::Value bind_crypto_secretbox_xsalsa20poly1305(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(3,"arguments message, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_secretbox_xsalsa20poly1305_KEYBYTES);

    NEW_BUFFER_AND_PTR(pmb, message_size + crypto_secretbox_xsalsa20poly1305_ZEROBYTES);

    // Fill the first crypto_secretbox_xsalsa20poly1305_ZEROBYTES with 0
    unsigned int i;
    for(i = 0; i < crypto_secretbox_xsalsa20poly1305_ZEROBYTES; i++) {
        pmb_ptr[i] = 0U;
    }

    //Copy the message to the new buffer
    memcpy((void*) (pmb_ptr + crypto_secretbox_xsalsa20poly1305_ZEROBYTES), (void *) message, message_size);
    message_size += crypto_secretbox_xsalsa20poly1305_ZEROBYTES;

    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if( crypto_secretbox_xsalsa20poly1305(ctxt_ptr, pmb_ptr, message_size, nonce, key) == 0) {
        return ctxt;
    } 
    
    return env.Null();
}

Napi::Value bind_crypto_secretbox_xsalsa20poly1305_open(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(3,"arguments cipherText, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(cipher_text);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_secretbox_xsalsa20poly1305_KEYBYTES);

    NEW_BUFFER_AND_PTR(message, cipher_text_size);

    // API requires that the first crypto_secretbox_xsalsa20poly1305_ZEROBYTES of msg be 0 so lets check
    if (cipher_text_size < crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES) {
        std::ostringstream oss;
        oss << "argument cipherText must have at least " << crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES << " bytes";
        Napi::Error::New(env, oss.str().c_str()).ThrowAsJavaScriptException();
        return env.Null();
    }

    unsigned int i;
    for(i = 0; i < crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES; i++) {
        if( cipher_text[i] ) break;
    }

    if (i < crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES) {
        std::ostringstream oss;
        oss << "the first " << crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        Napi::Error::New(env, oss.str().c_str()).ThrowAsJavaScriptException();
        return env.Null();
    }

    if (crypto_secretbox_xsalsa20poly1305_open(message_ptr, cipher_text, cipher_text_size, nonce, key) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text, cipher_text_size - crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (message_ptr + crypto_secretbox_xsalsa20poly1305_ZEROBYTES), cipher_text_size - crypto_secretbox_xsalsa20poly1305_ZEROBYTES);

        return plain_text;
    } else {
        return env.Null();
    }
}

/**
 * Register function calls in node binding
 */
void register_crypto_secretbox_xsalsa20poly1305(Napi::Env env, Napi::Object exports) {

    // Secret Box
    EXPORT(crypto_secretbox_xsalsa20poly1305);
    EXPORT(crypto_secretbox_xsalsa20poly1305_open);
    NEW_INT_PROP(crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES);
    NEW_INT_PROP(crypto_secretbox_xsalsa20poly1305_MACBYTES);
    NEW_INT_PROP(crypto_secretbox_xsalsa20poly1305_KEYBYTES);
    NEW_INT_PROP(crypto_secretbox_xsalsa20poly1305_NONCEBYTES);
    NEW_INT_PROP(crypto_secretbox_xsalsa20poly1305_ZEROBYTES);
}