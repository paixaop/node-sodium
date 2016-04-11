/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * int crypto_onetimeauth(
 *       unsigned char*  tok,
 *       const unsigned char * msg,
 *       unsigned long long mlen,
 *       const unsigned char * key)
 *
 * Parameters:
 *  [out] 	tok 	the generated authentication token.
 *  [in] 	msg 	the message to be authenticated.
 *  [in] 	mlen 	the length of msg.
 *  [in] 	key 	the key used to compute the token.
 */
NAN_METHOD(bind_crypto_onetimeauth) {
    Nan::EscapableHandleScope scope;

    ARGS(2,"arguments message, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_onetimeauth_KEYBYTES);

    NEW_BUFFER_AND_PTR(token, crypto_onetimeauth_BYTES);

    if( crypto_onetimeauth(token_ptr, message, message_size, key) == 0 ) {
        return info.GetReturnValue().Set(token);
    }
    
    return info.GetReturnValue().Set(Nan::Null());
}

/**
 * int crypto_onetimeauth_verify(
 *       unsigned char*  tok,
 *       const unsigned char * msg,
 *       unsigned long long mlen,
 *       const unsigned char * key)
 *
 * Parameters:
 *  [out] 	tok 	the generated authentication token.
 *  [in] 	msg 	the message to be authenticated.
 *  [in] 	mlen 	the length of msg.
 *  [in] 	key 	the key used to compute the token.
 */
NAN_METHOD(bind_crypto_onetimeauth_verify) {
    Nan::EscapableHandleScope scope;

    ARGS(3,"arguments token, message, and key must be buffers");
    ARG_TO_UCHAR_BUFFER_LEN(token, crypto_onetimeauth_BYTES);
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_onetimeauth_KEYBYTES);

    return info.GetReturnValue().Set(
        Nan::New<Integer>(crypto_onetimeauth_verify(token, message, message_size, key))
    );
}

/**
 * Register function calls in node binding
 */
void register_crypto_onetimeauth(Handle<Object> target) {
    // One Time Auth
    NEW_METHOD(crypto_onetimeauth);
    NEW_METHOD(crypto_onetimeauth_verify);
    NEW_INT_PROP(crypto_onetimeauth_BYTES);
    NEW_INT_PROP(crypto_onetimeauth_KEYBYTES);
    NEW_STRING_PROP(crypto_onetimeauth_PRIMITIVE);
}