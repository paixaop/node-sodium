/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * Encrypts and authenticates a message using the given secret key, and nonce.
 *
 * int crypto_secretbox(
 *    unsigned char *ctxt,
 *    const unsigned char *msg,
 *    unsigned long long mlen,
 *    const unsigned char *nonce,
 *    const unsigned char *key)
 *
 * Parameters:
 *    [out] ctxt 	the buffer for the cipher-text.
 *    [in] 	msg 	the message to be encrypted.
 *    [in] 	mlen 	the length of msg.
 *    [in] 	nonce 	a nonce with length crypto_box_NONCEBYTES.
 *    [in] 	key 	the shared secret key.
 *
 * Returns:
 *    0 if operation is successful.
 *
 * Precondition:
 *    first crypto_secretbox_ZEROBYTES of msg be all 0..
 *
 * Postcondition:
 *    first crypto_secretbox_BOXZERBYTES of ctxt be all 0.
 *    first mlen bytes of ctxt will contain the ciphertext.
 */
NAPI_METHOD(crypto_secretbox) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments message, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_secretbox_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_secretbox_KEYBYTES);

    NEW_BUFFER_AND_PTR(pmb, message_size + crypto_secretbox_ZEROBYTES);

    // Fill the first crypto_secretbox_ZEROBYTES with 0
    unsigned int i;
    for(i = 0; i < crypto_secretbox_ZEROBYTES; i++) {
        pmb_ptr[i] = 0U;
    }

    //Copy the message to the new buffer
    memcpy((void*) (pmb_ptr + crypto_secretbox_ZEROBYTES), (void *) message, message_size);
    message_size += crypto_secretbox_ZEROBYTES;

    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if( crypto_secretbox(ctxt_ptr, pmb_ptr, message_size, nonce, key) == 0) {
        return ctxt;
    } 
    
    return NAPI_NULL;
}

/**
 * Decrypts a ciphertext ctxt given the receivers private key, and senders public key.
 *
 * int crypto_secretbox_open(
 *    unsigned char *msg,
 *    const unsigned char *ctxt,
 *    unsigned long long clen,
 *    const unsigned char *nonce,
 *    const unsigned char *key)
 *
 * Parameters:
 *    [out] msg 	the buffer to place resulting plaintext.
 *    [in] 	ctxt 	the ciphertext to be decrypted.
 *    [in] 	clen 	the length of the ciphertext.
 *    [in] 	nonce 	a randomly generated nonce.
 *    [in] 	key 	the shared secret key.
 *
 * Returns:
 *    0 if successful and -1 if verification fails.
 *
 * Precondition:
 *    first crypto_secretbox_BOXZEROBYTES of ctxt be all 0.
 *    the nonce must be of length crypto_secretbox_NONCEBYTES
 *
 * Postcondition:
 *    first clen bytes of msg will contain the plaintext.
 *    first crypto_secretbox_ZEROBYTES of msg will be all 0.
 *
 * Warning:
 *    if verification fails msg may contain data from the computation.
 */
NAPI_METHOD(crypto_secretbox_open) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments cipherText, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(cipher_text);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_secretbox_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_secretbox_KEYBYTES);

    NEW_BUFFER_AND_PTR(message, cipher_text_size);

    // API requires that the first crypto_secretbox_ZEROBYTES of msg be 0 so lets check
    if (cipher_text_size < crypto_secretbox_BOXZEROBYTES) {
        THROW_ERROR("argument cipherText must have at least crypto_secretbox_BOXZEROBYTES bytes");
    }

    unsigned int i;
    for(i = 0; i < crypto_secretbox_BOXZEROBYTES; i++) {
        if( cipher_text[i] ) break;
    }

    if (i < crypto_secretbox_BOXZEROBYTES) {
        THROW_ERROR("the first crypto_secretbox_BOXZEROBYTES bytes of argument cipherText must be 0");
    }

    if (crypto_secretbox_open(message_ptr, cipher_text, cipher_text_size, nonce, key) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text, cipher_text_size - crypto_secretbox_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (message_ptr + crypto_secretbox_ZEROBYTES), cipher_text_size - crypto_secretbox_ZEROBYTES);

        return plain_text;
    } else {
        return NAPI_NULL;
    }
}

/**
 * Encrypts and authenticates a message using the given secret key, and nonce.
 *
 * int crypto_secretbox_easy(
 *    unsigned char *ctxt,
 *    const unsigned char *msg,
 *    unsigned long long mlen,
 *    const unsigned char *nonce,
 *    const unsigned char *key)
 *
 * Parameters:
 *    [out] ctxt   the buffer for the cipher-text.
 *    [in]   msg   the message to be encrypted.
 *    [in]   mlen   the length of msg.
 *    [in]   nonce   a nonce with length crypto_box_NONCEBYTES.
 *    [in]   key   the shared secret key.
 *
 * Returns:
 *    0 if operation is successful.
 *
 * Precondition:
 *
 * Postcondition:
 *    first mlen + crypto_secretbox_MACLENGTH bytes of ctxt will contain the ciphertext.
 */
NAPI_METHOD(crypto_secretbox_easy) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments message, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_secretbox_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_secretbox_KEYBYTES);

    NEW_BUFFER_AND_PTR(c, message_size + crypto_secretbox_MACBYTES);

    if (crypto_secretbox_easy(c_ptr, message, message_size, nonce, key) == 0) {
        return c;
    } 
    
    return NAPI_NULL;
}

/**
 * int crypto_secretbox_open_easy(
 *    unsigned char *msg,
 *    const unsigned char *ctxt,
 *    unsigned long long clen,
 *    const unsigned char *nonce,
 *    const unsigned char *key)
 * Parameters:
 *    [out] msg   the buffer to place resulting plaintext.
 *    [in]   ctxt   the ciphertext to be decrypted.
 *    [in]   clen   the length of the ciphertext.
 *    [in]   nonce   a randomly generated nonce.
 *    [in]   key   the shared secret key.
 *
 * Returns:
 *    0 if successful and -1 if verification fails.
 *
 * Precondition:
 *    the nonce must be of length crypto_secretbox_NONCEBYTES
 *
 * Postcondition:
 *    first clen - crypto_secretbox_MACBYTES bytes of msg will contain the plaintext.
 *
 * Warning:
 *    if verification fails msg may contain data from the computation.
 */

NAPI_METHOD(crypto_secretbox_open_easy) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments message, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(cipher_text);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_secretbox_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_secretbox_KEYBYTES);

    NEW_BUFFER_AND_PTR(c, cipher_text_size - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(c_ptr, cipher_text, cipher_text_size, nonce, key) == 0) {
        return c;
    }
    
    return NAPI_NULL;
}

/*
int crypto_secretbox_detached(unsigned char *c,
                              unsigned char *mac,
                              const unsigned char *m,
                              unsigned long long mlen,
                              const unsigned char *n,
                              const unsigned char *k);
*/
NAPI_METHOD(crypto_secretbox_detached) {
    Napi::Env env = info.Env();

    ARGS(4, "arguments mac, message, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER_LEN(mac, crypto_secretbox_MACBYTES);
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_secretbox_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_secretbox_KEYBYTES);

    NEW_BUFFER_AND_PTR(c, message_size);

    if (crypto_secretbox_detached(c_ptr, mac, message, message_size, nonce, key) == 0) {
        return c;
    }
    
    return NAPI_NULL;
}

/*
int crypto_secretbox_open_detached(unsigned char *m,
                                   const unsigned char *c,
                                   const unsigned char *mac,
                                   unsigned long long clen,
                                   const unsigned char *n,
                                   const unsigned char *k)
*/
NAPI_METHOD(crypto_secretbox_open_detached) {
    Napi::Env env = info.Env();

    ARGS(4, "arguments encrypted message, mac, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(c);
    ARG_TO_UCHAR_BUFFER_LEN(mac, crypto_secretbox_MACBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_secretbox_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_secretbox_KEYBYTES);

    NEW_BUFFER_AND_PTR(m, c_size);

    if (crypto_secretbox_open_detached(m_ptr, c, mac, c_size, nonce, key) == 0) {
        return m;
    }
    
    return NAPI_NULL;
}

/**
 * Register function calls in node binding
 */
void register_crypto_secretbox(Napi::Env env, Napi::Object exports) {

    // Secret Box
    EXPORT(crypto_secretbox);
    EXPORT(crypto_secretbox_open);
    EXPORT(crypto_secretbox_easy);
    EXPORT(crypto_secretbox_open_easy);
    EXPORT(crypto_secretbox_detached);
    EXPORT(crypto_secretbox_open_detached);
    
    EXPORT_INT(crypto_secretbox_BOXZEROBYTES);
    EXPORT_INT(crypto_secretbox_MACBYTES);
    EXPORT_INT(crypto_secretbox_KEYBYTES);
    EXPORT_INT(crypto_secretbox_NONCEBYTES);
    EXPORT_INT(crypto_secretbox_ZEROBYTES);
    EXPORT_STRING(crypto_secretbox_PRIMITIVE);
}