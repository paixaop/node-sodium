/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * Signs a given message using the signer's signing key.
 *
 * int crypto_sign(
 *    unsigned char * sig,
 *    unsigned long long * slen,
 *    const unsigned char * msg,
 *    unsigned long long mlen,
 *    const unsigned char * sk)
 *
 * Parameters:
 *    [out] sig     the resulting signature.
 *    [out] slen    the length of the signature.
 *    [in] 	msg     the message to be signed.
 *    [in] 	mlen    the length of the message.
 *    [in] 	sk 	    the signing key.
 *
 * Returns:
 *    0 if operation successful
 *
 * Precondition:
 *    sig must be of length mlen+crypto_sign_BYTES
 *    sk must be of length crypto_sign_SECRETKEYBYTES
 */
NAN_METHOD(bind_crypto_sign) {
    Nan::EscapableHandleScope scope;

    ARGS(2,"arguments message, and secretKey must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(secretKey, crypto_sign_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(sig, message_size + crypto_sign_BYTES);

    unsigned long long slen = 0;

    if (crypto_sign(sig_ptr, &slen, message, message_size, secretKey) == 0) {
        return info.GetReturnValue().Set(sig);
    } else {
        return;
    }
}

/**
 * Signs a given message using the signer's signing key (detached mode).
 *
 * int crypto_sign_detached(
 *    unsigned char * sig,
 *    unsigned long long * slen,
 *    const unsigned char * msg,
 *    unsigned long long mlen,
 *    const unsigned char * sk)
 *
 * Parameters:
 *    [out] sig     the resulting signature.
 *    [out] slen    the length of the signature.
 *    [in]  msg     the message to be signed.
 *    [in]  mlen    the length of the message.
 *    [in]  sk      the signing key.
 *
 * Returns:
 *    0 if operation successful
 *
 * Precondition:
 *    sig must be of length crypto_sign_BYTES
 *    sk must be of length crypto_sign_SECRETKEYBYTES
 */
NAN_METHOD(bind_crypto_sign_detached) {
    Nan::EscapableHandleScope scope;

    ARGS(2,"arguments message, and secretKey must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(secretKey, crypto_sign_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(sig, crypto_sign_BYTES);

    unsigned long long slen = 0;

    if (crypto_sign_detached(sig_ptr, &slen, message, message_size, secretKey) == 0) {
        return info.GetReturnValue().Set(sig);
    } else {
        return info.GetReturnValue().Set(Nan::Undefined());
    }
}

/**
 * Generates a signing/verification key pair.
 *
 * int crypto_sign_keypair(
 *    unsigned char * vk,
 *    unsigned char * sk)
 *
 * Parameters:
 *    [out] vk 	the verification key.
 *    [out] sk 	the signing key.
 *
 * Returns:
 *    0 if operation successful.
 *
 * Precondition:
 *    the buffer for vk must be at least crypto_sign_PUBLICKEYBYTES in length
 *    the buffer for sk must be at least crypto_sign_SECRETKEYTBYTES in length
 *
 * Postcondition:
 *    first crypto_sign_PUBLICKEYTBYTES of vk will be the key data.
 *    first crypto_sign_SECRETKEYTBYTES of sk will be the key data.
 */
NAN_METHOD(bind_crypto_sign_keypair) {
    Nan::EscapableHandleScope scope;

    NEW_BUFFER_AND_PTR(vk, crypto_sign_PUBLICKEYBYTES);
    NEW_BUFFER_AND_PTR(sk, crypto_sign_SECRETKEYBYTES);

    if (crypto_sign_keypair(vk_ptr, sk_ptr) == 0) {
        Local<Object> result = Nan::New<Object>();
        result->ForceSet(Nan::New<String>("publicKey").ToLocalChecked(), vk, DontDelete);
        result->ForceSet(Nan::New<String>("secretKey").ToLocalChecked(), sk, DontDelete);

        return info.GetReturnValue().Set(result);
    } else {
        return;
    }
}

/**
 * Deterministically generate a signing/verification key pair from a seed.
 *
 * int crypto_sign_keypair(
 *    unsigned char * vk,
 *    unsigned char * sk,
 *    const unsigned char * ps)
 *
 * Parameters:
 *    [out] vk  the verification key.
 *    [out] sk  the signing key.
 *    [in]  sd  the seed for the key-pair.
 *
 * Returns:
 *    0 if operation successful.
 *
 * Precondition:
 *    the buffer for vk must be at least crypto_sign_PUBLICKEYBYTES in length
 *    the buffer for sk must be at least crypto_sign_SECRETKEYTBYTES in length
 *    the buffer for sd must be at least crypto_sign_SEEDBYTES in length
 *
 * Postcondition:
 *    first crypto_sign_PUBLICKEYTBYTES of vk will be the key data.
 *    first crypto_sign_SECRETKEYTBYTES of sk will be the key data.
 */
NAN_METHOD(bind_crypto_sign_seed_keypair) {
    Nan::EscapableHandleScope scope;

    ARGS(1,"the argument seed must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(sd, crypto_sign_SEEDBYTES);

    NEW_BUFFER_AND_PTR(vk, crypto_sign_PUBLICKEYBYTES);
    NEW_BUFFER_AND_PTR(sk, crypto_sign_SECRETKEYBYTES);

    if (crypto_sign_seed_keypair(vk_ptr, sk_ptr, sd) == 0) {
        Local<Object> result = Nan::New<Object>();

        result->ForceSet(Nan::New<String>("publicKey").ToLocalChecked(), vk, DontDelete);
        result->ForceSet(Nan::New<String>("secretKey").ToLocalChecked(), sk, DontDelete);

        return info.GetReturnValue().Set(result);
    } else {
        return;
    }
}

/**
 * Verifies the signed message sig using the signer's verification key.
 *
 * int crypto_sign_open(
 *    unsigned char * msg,
 *    unsigned long long * mlen,
 *    const unsigned char * sig,
 *    unsigned long long smlen,
 *    const unsigned char * vk)
 *
 * Parameters:
 *
 *    [out] msg     the resulting message.
 *    [out] mlen    the length of msg.
 *    [in] 	sig     the signed message.
 *    [in] 	smlen   length of the signed message.
 *    [in] 	vk 	    the verification key.
 *
 * Returns:
 *    0 if successful, -1 if verification fails.
 *
 * Precondition:
 *    length of msg must be at least smlen
 *
 * Warning:
 *    if verification fails msg may contain data from the computation.
 */
NAN_METHOD(bind_crypto_sign_open) {
    Nan::EscapableHandleScope scope;

    ARGS(2,"arguments signedMessage and verificationKey must be buffers");
    ARG_TO_UCHAR_BUFFER(signedMessage);
    ARG_TO_UCHAR_BUFFER_LEN(publicKey, crypto_sign_PUBLICKEYBYTES);

    unsigned long long mlen = 0;
    NEW_BUFFER_AND_PTR(msg, signedMessage_size);

    if (crypto_sign_open(msg_ptr, &mlen, signedMessage, signedMessage_size, publicKey) == 0) {
        NEW_BUFFER_AND_PTR(m, mlen);
        memcpy(m_ptr, msg_ptr, mlen);

        return info.GetReturnValue().Set(m);
    } else {
        return;
    }
}

/**
 * Verifies the signed message sig using the signer's verification key.
 *
 * int crypto_sign_verify_detached(
 *    const unsigned char * sig,
 *    const unsigned char * msg,
 *    unsigned long long mlen,
 *    const unsigned char * vk)
 *
 * Parameters:
 *
 *    [in]  sig     the signature
 *    [in] msg     the message.
 *    [in] mlen    the length of msg.
 *    [in]  vk      the verification key.
 *
 * Returns:
 *    0 if successful, -1 if verification fails.
 *
 * Precondition:
 *    length of sig must be crypto_sign_BYTES
 *
 * Warning:
 *    if verification fails msg may contain data from the computation.
 */
NAN_METHOD(bind_crypto_sign_verify_detached) {
    Nan::EscapableHandleScope scope;

    ARGS(2,"arguments signedMessage and verificationKey must be buffers");
    ARG_TO_UCHAR_BUFFER_LEN(signature, crypto_sign_BYTES);
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(publicKey, crypto_sign_PUBLICKEYBYTES);

    if (crypto_sign_verify_detached(signature, message, message_size, publicKey) == 0) {
        return info.GetReturnValue().Set(Nan::True());
    } else {
        return info.GetReturnValue().Set(Nan::False());
    }
}

/**
 * Convert a ed25519 signing public key to a curve25519 exchange key.
 *
 * Parameters:
 *    [out] curve25519_pk the public exchange key.
 *    [in]  ed25519_pk    the public signing key.
 *
 * Returns:
 *    0
 *
 * Precondition:
 *    ed25519_pk must be a ed25519 public key.
 */
NAN_METHOD(bind_crypto_sign_ed25519_pk_to_curve25519) {
    Nan::EscapableHandleScope scope;

    ARGS(1, "argument ed25519_pk must be a buffer")
    ARG_TO_UCHAR_BUFFER_LEN(ed25519_pk, crypto_sign_PUBLICKEYBYTES);
    
    NEW_BUFFER_AND_PTR(curve25519_pk, crypto_box_PUBLICKEYBYTES);

    if( crypto_sign_ed25519_pk_to_curve25519(curve25519_pk_ptr, ed25519_pk) != 0) {
      return Nan::ThrowError("crypto_sign_ed25519_pk_to_curve25519 conversion failed");
    }

    return info.GetReturnValue().Set(curve25519_pk);
}


/**
 * Convert a ed25519 signing secret key to a curve25519 exchange key.
 *
 * Parameters:
 *    [out] curve25519_sk the secret exchange key.
 *    [in]  ed25519_sk    the secret signing key.
 *
 * Returns:
 *    0
 *
 * Precondition:
 *    ed25519_sk must be a ed25519 secret key.
 */
NAN_METHOD(bind_crypto_sign_ed25519_sk_to_curve25519) {
    Nan::EscapableHandleScope scope;

    ARGS(1, "argument ed25519_sk must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(ed25519_sk, crypto_sign_SECRETKEYBYTES);
    
    NEW_BUFFER_AND_PTR(curve25519_sk, crypto_box_SECRETKEYBYTES);

    if( crypto_sign_ed25519_sk_to_curve25519(curve25519_sk_ptr, ed25519_sk) != 0) {
      return Nan::ThrowError("crypto_sign_ed25519_pk_to_curve25519 conversion failed");
    }

    return info.GetReturnValue().Set(curve25519_sk);
}

/**
 * Register function calls in node binding
 */
void register_crypto_sign(Handle<Object> target) {
     // Sign
    NEW_METHOD(crypto_sign);
    NEW_METHOD(crypto_sign_detached);
    NEW_METHOD(crypto_sign_keypair);
    NEW_METHOD(crypto_sign_seed_keypair);
    NEW_METHOD(crypto_sign_open);
    NEW_METHOD(crypto_sign_verify_detached);
    NEW_METHOD(crypto_sign_ed25519_pk_to_curve25519);
    NEW_METHOD(crypto_sign_ed25519_sk_to_curve25519);
    NEW_INT_PROP(crypto_sign_BYTES);
    NEW_INT_PROP(crypto_sign_PUBLICKEYBYTES);
    NEW_INT_PROP(crypto_sign_SECRETKEYBYTES);
    NEW_STRING_PROP(crypto_sign_PRIMITIVE);
}