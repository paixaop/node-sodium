/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"
#include "crypto_auth_algos.h"
/**
 * int crypto_auth(
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
NAN_METHOD(bind_crypto_auth) {
    Nan::EscapableHandleScope scope;

    ARGS(2,"arguments message, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(msg);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_auth_KEYBYTES);

    NEW_BUFFER_AND_PTR(token, crypto_auth_BYTES);

    if( crypto_auth(token_ptr, msg, msg_size, key) == 0 ) {
        return info.GetReturnValue().Set(token);
    }
    
    return info.GetReturnValue().Set(Nan::Null());
}

/**
 * int crypto_auth_verify(
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
NAN_METHOD(bind_crypto_auth_verify) {
    Nan::EscapableHandleScope scope;

    ARGS(3,"arguments token, message, and key must be buffers");
    ARG_TO_UCHAR_BUFFER_LEN(token, crypto_auth_BYTES);
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_auth_KEYBYTES);

    return info.GetReturnValue().Set(
        Nan::New<Integer>(crypto_auth_verify(token, message, message_size, key))
    );
}

/**
 * Register function calls in node binding
 */
void register_crypto_auth(Handle<Object> target) {
    // Auth
    NEW_METHOD_ALIAS(crypto_auth, crypto_auth_hmacsha512256);
    NEW_METHOD_ALIAS(crypto_auth_verify, crypto_auth_hmacsha512256_verify);
    
    NEW_INT_PROP(crypto_auth_BYTES);
    NEW_INT_PROP(crypto_auth_KEYBYTES);
    NEW_STRING_PROP(crypto_auth_PRIMITIVE);   
}