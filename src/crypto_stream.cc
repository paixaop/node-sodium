/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

#include "crypto_streams.h"

/**
 * int crypto_stream(
 *    unsigned char * stream,
 *    unsigned long long slen,
 *    const unsigned char * nonce,
 *    const unsigned char * key)
 *
 * Generates a stream using the given secret key and nonce.
 *
 * Parameters:
 *    [out] stream  the generated stream.
 *    [out] slen    the length of the generated stream.
 *    [in]  nonce   the nonce used to generate the stream.
 *    [in]  key     the key used to generate the stream.
 *
 * Returns:
 *    0 if operation successful
 */
NAN_METHOD(bind_crypto_stream) {
    Nan::EscapableHandleScope scope;

    ARGS(3,"argument length must be a positive number, arguments nonce, and key must be buffers");
    ARG_TO_POSITIVE_NUMBER(slen);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_stream_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_stream_KEYBYTES);

    NEW_BUFFER_AND_PTR(stream, slen);

    if (crypto_stream(stream_ptr, slen, nonce, key) == 0) {
        return info.GetReturnValue().Set(stream);
    }
    
    return info.GetReturnValue().Set(Nan::Null());
}

/**
 * int crypto_stream_xor(
 *    unsigned char *c,
 *    const unsigned char *m,
 *    unsigned long long mlen,
 *    const unsigned char *n,
 *    const unsigned char *k)
 *
 * Parameters:
 *    [out] ctxt 	buffer for the resulting ciphertext.
 *    [in] 	msg 	the message to be encrypted.
 *    [in] 	mlen 	the length of the message.
 *    [in] 	nonce 	the nonce used during encryption.
 *    [in] 	key 	secret key used during encryption.
 *
 * Returns:
 *    0 if operation successful.
 *
 * Precondition:
 *    ctxt must have length minimum mlen.
 *    nonce must have length minimum crypto_stream_NONCEBYTES.
 *    key must have length minimum crpyto_stream_KEYBYTES
 */
NAN_METHOD(bind_crypto_stream_xor) {
    Nan::EscapableHandleScope scope;

    ARGS(3,"arguments message, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_stream_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_stream_KEYBYTES);

    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if (crypto_stream_xor(ctxt_ptr, message, message_size, nonce, key) == 0) {
        return info.GetReturnValue().Set(ctxt);
    }
    
    return info.GetReturnValue().Set(Nan::Null());
}

/**
 * Register function calls in node binding
 */
void register_crypto_stream(Handle<Object> target) {
    // Stream
    NEW_METHOD_ALIAS(crypto_stream, crypto_stream_xsalsa20);
    NEW_METHOD_ALIAS(crypto_stream_xor, crypto_stream_xsalsa20_xor);
    
    NEW_INT_PROP(crypto_stream_KEYBYTES);
    NEW_INT_PROP(crypto_stream_NONCEBYTES);
    NEW_STRING_PROP(crypto_stream_PRIMITIVE);
}