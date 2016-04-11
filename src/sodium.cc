/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"
#include "node_sodium_register.h"

// get handle to the global object
Local<Object> globalObj = Nan::GetCurrentContext()->Global();

// Retrieve the buffer constructor function
Local<Function> bufferConstructor =
       Local<Function>::Cast(globalObj->Get(Nan::New<String>("Buffer").ToLocalChecked()));

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

    NUMBER_OF_MANDATORY_ARGS(2,"arguments message, and key must be buffers");

    GET_ARG_AS_UCHAR(0, msg);
    GET_ARG_AS_UCHAR_LEN(1, key, crypto_auth_KEYBYTES);

    NEW_BUFFER_AND_PTR(token, crypto_auth_BYTES);

    if( crypto_auth(token_ptr, msg, msg_size, key) == 0 ) {
        return info.GetReturnValue().Set(token);
    } else {
        return info.GetReturnValue().Set(Nan::Null());
    }
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

    NUMBER_OF_MANDATORY_ARGS(3,"arguments token, message, and key must be buffers");

    GET_ARG_AS_UCHAR_LEN(0, token, crypto_auth_BYTES);
    GET_ARG_AS_UCHAR(1, message);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_auth_KEYBYTES);

    return info.GetReturnValue().Set(
        Nan::New<Integer>(crypto_auth_verify(token, message, message_size, key))
    );
}

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

    NUMBER_OF_MANDATORY_ARGS(2,"arguments message, and key must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, key, crypto_onetimeauth_KEYBYTES);

    NEW_BUFFER_AND_PTR(token, crypto_onetimeauth_BYTES);

    if( crypto_onetimeauth(token_ptr, message, message_size, key) == 0 ) {
        return info.GetReturnValue().Set(token);
    } else {
        return info.GetReturnValue().Set(Nan::Null());
    }
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

    NUMBER_OF_MANDATORY_ARGS(3,"arguments token, message, and key must be buffers");

    GET_ARG_AS_UCHAR_LEN(0, token, crypto_onetimeauth_BYTES);
    GET_ARG_AS_UCHAR(1, message);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_onetimeauth_KEYBYTES);

    return info.GetReturnValue().Set(
        Nan::New<Integer>(crypto_onetimeauth_verify(token, message, message_size, key))
    );
}

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
 *    [out]  slen    the length of the generated stream.
 *    [in]  nonce   the nonce used to generate the stream.
 *    [in]  key     the key used to generate the stream.
 *
 * Returns:
 *    0 if operation successful
 */
NAN_METHOD(bind_crypto_stream) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"argument length must be a positive number, arguments nonce, and key must be buffers");

    if (!info[0]->IsUint32())
        return Nan::ThrowError("argument length must be positive number");

    unsigned long long slen = info[0]->ToUint32()->Value();

    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_stream_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_stream_KEYBYTES);

    NEW_BUFFER_AND_PTR(stream, slen);

    if (crypto_stream(stream_ptr, slen, nonce, key) == 0) {
        return info.GetReturnValue().Set(stream);
    } else {
        return;
    }
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

    NUMBER_OF_MANDATORY_ARGS(3,"arguments message, nonce, and key must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_stream_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_stream_KEYBYTES);

    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if (crypto_stream_xor(ctxt_ptr, message, message_size, nonce, key) == 0) {
        return info.GetReturnValue().Set(ctxt);
    } else {
        return;
    }
}

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
NAN_METHOD(bind_crypto_secretbox) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments message, nonce, and key must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_secretbox_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_secretbox_KEYBYTES);

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
        return info.GetReturnValue().Set(ctxt);
    } else {
        return;
    }
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
NAN_METHOD(bind_crypto_secretbox_open) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments cipherText, nonce, and key must be buffers");

    GET_ARG_AS_UCHAR(0, cipher_text);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_secretbox_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_secretbox_KEYBYTES);

    NEW_BUFFER_AND_PTR(message, cipher_text_size);

    // API requires that the first crypto_secretbox_ZEROBYTES of msg be 0 so lets check
    if (cipher_text_size < crypto_secretbox_BOXZEROBYTES) {
        std::ostringstream oss;
        oss << "argument cipherText must have at least " << crypto_secretbox_BOXZEROBYTES << " bytes";
        return Nan::ThrowError(oss.str().c_str());
    }

    unsigned int i;
    for(i = 0; i < crypto_secretbox_BOXZEROBYTES; i++) {
        if( cipher_text[i] ) break;
    }

    if (i < crypto_secretbox_BOXZEROBYTES) {
        std::ostringstream oss;
        oss << "the first " << crypto_secretbox_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        return Nan::ThrowError(oss.str().c_str());
    }

    if (crypto_secretbox_open(message_ptr, cipher_text, cipher_text_size, nonce, key) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text, cipher_text_size - crypto_secretbox_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (message_ptr + crypto_secretbox_ZEROBYTES), cipher_text_size - crypto_secretbox_ZEROBYTES);

        return info.GetReturnValue().Set(plain_text);
    } else {
        return;
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

NAN_METHOD(bind_crypto_secretbox_easy) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments message, nonce, and key must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_secretbox_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_secretbox_KEYBYTES);

    NEW_BUFFER_AND_PTR(c, message_size + crypto_secretbox_MACBYTES);

    if (crypto_secretbox_easy(c_ptr, message, message_size, nonce, key) == 0) {
        return info.GetReturnValue().Set(c);
    } else {
        return;
    }
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

NAN_METHOD(bind_crypto_secretbox_open_easy) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments message, nonce, and key must be buffers");

    GET_ARG_AS_UCHAR(0, cipher_text);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_secretbox_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_secretbox_KEYBYTES);

    NEW_BUFFER_AND_PTR(c, cipher_text_size - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(c_ptr, cipher_text, cipher_text_size, nonce, key) == 0) {
        return info.GetReturnValue().Set(c);
    } else {
        return;
    }
}


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

    NUMBER_OF_MANDATORY_ARGS(2,"arguments message, and secretKey must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, secretKey, crypto_sign_SECRETKEYBYTES);

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

    NUMBER_OF_MANDATORY_ARGS(2,"arguments message, and secretKey must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, secretKey, crypto_sign_SECRETKEYBYTES);

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

    NUMBER_OF_MANDATORY_ARGS(1,"the argument seed must be a buffer");

    GET_ARG_AS_UCHAR_LEN(0, sd, crypto_sign_SEEDBYTES);

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

    NUMBER_OF_MANDATORY_ARGS(2,"arguments signedMessage and verificationKey must be buffers");

    GET_ARG_AS_UCHAR(0, signedMessage);
    GET_ARG_AS_UCHAR_LEN(1, publicKey, crypto_sign_PUBLICKEYBYTES);

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

    NUMBER_OF_MANDATORY_ARGS(2,"arguments signedMessage and verificationKey must be buffers");

    GET_ARG_AS_UCHAR_LEN(0, signature, crypto_sign_BYTES);
    GET_ARG_AS_UCHAR(1, message);
    GET_ARG_AS_UCHAR_LEN(2, publicKey, crypto_sign_PUBLICKEYBYTES);

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

    NUMBER_OF_MANDATORY_ARGS(1, "argument ed25519_pk must be a buffer")

    GET_ARG_AS_UCHAR_LEN(0, ed25519_pk, crypto_sign_PUBLICKEYBYTES);
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

    NUMBER_OF_MANDATORY_ARGS(1, "argument ed25519_sk must be a buffer");

    GET_ARG_AS_UCHAR_LEN(0, ed25519_sk, crypto_sign_SECRETKEYBYTES);
    NEW_BUFFER_AND_PTR(curve25519_sk, crypto_box_SECRETKEYBYTES);

    if( crypto_sign_ed25519_sk_to_curve25519(curve25519_sk_ptr, ed25519_sk) != 0) {
      return Nan::ThrowError("crypto_sign_ed25519_pk_to_curve25519 conversion failed");
    }

    return info.GetReturnValue().Set(curve25519_sk);
}



/**
 * Encrypts a message given the senders secret key, and receivers public key.
 * int crypto_box	(
 *    unsigned char * ctxt,
 *    const unsigned char * msg,
 *    unsigned long long mlen,
 *    const unsigned char * nonce,
 *    const unsigned char * pk,
 *    const unsigned char * sk)
 *
 * Parameters:
 *    [out] ctxt    the buffer for the cipher-text.
 *    [in] 	msg     the message to be encrypted.
 *    [in] 	mlen    the length of msg.
 *    [in] 	nonce   a randomly generated nonce.
 *    [in] 	pk 	    the receivers public key, used for encryption.
 *    [in] 	sk 	    the senders private key, used for signing.
 *
 * Returns:
 *    0 if operation is successful.
 *
 * Precondition:
 *    first crypto_box_ZEROBYTES of msg be all 0.
 *    the nonce must have size crypto_box_NONCEBYTES.
 *
 * Postcondition:
 *    first crypto_box_BOXZEROBYTES of ctxt be all 0.
 *    first mlen bytes of ctxt will contain the ciphertext.
 */
NAN_METHOD(bind_crypto_box) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(4,"arguments message, nonce, publicKey and secretKey must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, publicKey, crypto_box_PUBLICKEYBYTES);
    GET_ARG_AS_UCHAR_LEN(3, secretKey, crypto_box_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(msg, message_size + crypto_box_ZEROBYTES);

    // Fill the first crypto_box_ZEROBYTES with 0
    unsigned int i;
    for(i = 0; i < crypto_box_ZEROBYTES; i++) {
       msg_ptr[i] = 0U;
    }

    //Copy the message to the new buffer
    memcpy((void*) (msg_ptr + crypto_box_ZEROBYTES), (void *) message, message_size);
    message_size += crypto_box_ZEROBYTES;

    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if (crypto_box(ctxt_ptr, msg_ptr, message_size, nonce, publicKey, secretKey) == 0) {
        return info.GetReturnValue().Set(ctxt);
    } else {
        return;
    }
}

/**
 * Encrypts a message given the senders secret key, and receivers public key.
 * int crypto_box_easy   (
 *    unsigned char * ctxt,
 *    const unsigned char * msg,
 *    unsigned long long mlen,
 *    const unsigned char * nonce,
 *    const unsigned char * pk,
 *    const unsigned char * sk)
 *
 * Parameters:
 *    [out] ctxt    the buffer for the cipher-text.
 *    [in]  msg     the message to be encrypted.
 *    [in]  mlen    the length of msg.
 *    [in]  nonce   a randomly generated nonce.
 *    [in]  pk      the receivers public key, used for encryption.
 *    [in]  sk      the senders private key, used for signing.
 *
 * Returns:
 *    0 if operation is successful.
 *
 * Precondition:
 *    the nonce must have size crypto_box_NONCEBYTES.
 *
 * Postcondition:
 *    first mlen bytes of ctxt will contain the ciphertext.
 */
NAN_METHOD(bind_crypto_box_easy) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(4,"arguments message, nonce, publicKey and secretKey must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, publicKey, crypto_box_PUBLICKEYBYTES);
    GET_ARG_AS_UCHAR_LEN(3, secretKey, crypto_box_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(ctxt, message_size + crypto_box_MACBYTES);

    if (crypto_box_easy(ctxt_ptr, message, message_size, nonce, publicKey, secretKey) == 0) {
        return info.GetReturnValue().Set(ctxt);
    } else {
        return;
    }
}


/**
 * Randomly generates a secret key and a corresponding public key.
 *
 * int crypto_box_keypair(
 *    unsigned char * pk,
 *    unsigned char * sk)
 *
 * Parameters:
 *    [out] pk  the buffer for the public key with length crypto_box_PUBLICKEYBYTES
 *    [out] sk  the buffer for the private key with length crypto_box_SECRETKEYTBYTES
 *
 * Returns:
 *    0 if generation successful.
 *
 * Precondition:
 *    the buffer for pk must be at least crypto_box_PUBLICKEYBYTES in length
 *    the buffer for sk must be at least crypto_box_SECRETKEYTBYTES in length
 *
 * Postcondition:
 *    first crypto_box_PUBLICKEYTBYTES of pk will be the key data.
 *    first crypto_box_SECRETKEYTBYTES of sk will be the key data.
 */
NAN_METHOD(bind_crypto_box_keypair) {
    Nan::EscapableHandleScope scope;

    NEW_BUFFER_AND_PTR(pk, crypto_box_PUBLICKEYBYTES);
    NEW_BUFFER_AND_PTR(sk, crypto_box_SECRETKEYBYTES);

    if (crypto_box_keypair(pk_ptr, sk_ptr) == 0) {
        Local<Object> result = Nan::New<Object>();

        result->ForceSet(Nan::New<String>("publicKey").ToLocalChecked(), pk, DontDelete);
        result->ForceSet(Nan::New<String>("secretKey").ToLocalChecked(), sk, DontDelete);

        return info.GetReturnValue().Set(result);
    } else {
        return;
    }
}

/**
 * Decrypts a ciphertext ctxt given the receivers private key, and senders public key.
 *
 * int crypto_box_open(
 *    unsigned char *       msg,
 *    const unsigned char * ctxt,
 *    unsigned long long    clen,
 *    const unsigned char * nonce,
 *    const unsigned char * pk,
 *    const unsigned char * sk)
 *
 * Parameters:
 *     [out] msg     the buffer to place resulting plaintext.
 *     [in]  ctxt    the ciphertext to be decrypted.
 *     [in]  clen    the length of the ciphertext.
 *     [in]  nonce   a randomly generated.
 *     [in]  pk      the senders public key, used for verification.
 *     [in]  sk      the receivers private key, used for decryption.
 *
 Returns:
 *     0 if successful and -1 if verification fails.
 *
 Precondition:
 *     first crypto_box_BOXZEROBYTES of ctxt be all 0.
 *     the nonce must have size crypto_box_NONCEBYTES.
 *
 * Postcondition:
 *     first clen bytes of msg will contain the plaintext.
 *     first crypto_box_ZEROBYTES of msg will be all 0.
 */
NAN_METHOD(bind_crypto_box_open) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(4,"arguments cipherText, nonce, publicKey and secretKey must be buffers");

    GET_ARG_AS_UCHAR(0, cipherText);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, publicKey, crypto_box_PUBLICKEYBYTES);
    GET_ARG_AS_UCHAR_LEN(3, secretKey, crypto_box_SECRETKEYBYTES);

    // API requires that the first crypto_box_BOXZEROBYTES of msg be 0 so lets check
    if (cipherText_size < crypto_box_BOXZEROBYTES) {
        std::ostringstream oss;
        oss << "argument cipherText must have a length of at least " << crypto_box_BOXZEROBYTES << " bytes";
        return Nan::ThrowError(oss.str().c_str());
    }

    unsigned int i;

    for (i = 0; i < crypto_box_BOXZEROBYTES; i++) {
        if( cipherText[i] ) break;
    }

    if (i < crypto_box_BOXZEROBYTES) {
        std::ostringstream oss;
        oss << "the first " << crypto_box_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        return Nan::ThrowError(oss.str().c_str());
    }

    NEW_BUFFER_AND_PTR(msg, cipherText_size);

    if (crypto_box_open(msg_ptr, cipherText, cipherText_size, nonce, publicKey, secretKey) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text, cipherText_size - crypto_box_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (msg_ptr + crypto_box_ZEROBYTES), cipherText_size - crypto_box_ZEROBYTES);

        return info.GetReturnValue().Set(plain_text);
    } else {
        return;
    }
}

/**
 * Decrypts a ciphertext ctxt given the receivers private key, and senders public key.
 *
 * int crypto_box_open_easy(
 *    unsigned char *       msg,
 *    const unsigned char * ctxt,
 *    unsigned long long    clen,
 *    const unsigned char * nonce,
 *    const unsigned char * pk,
 *    const unsigned char * sk)
 *
 * Parameters:
 *     [out] msg     the buffer to place resulting plaintext.
 *     [in]  ctxt    the ciphertext to be decrypted.
 *     [in]  clen    the length of the ciphertext.
 *     [in]  nonce   a randomly generated.
 *     [in]  pk      the senders public key, used for verification.
 *     [in]  sk      the receivers private key, used for decryption.
 *
 Returns:
 *     0 if successful and -1 if verification fails.
 *
 Precondition:
 *     the nonce must have size crypto_box_NONCEBYTES.
 *
 * Postcondition:
 *     first clen bytes of msg will contain the plaintext.
 */
NAN_METHOD(bind_crypto_box_open_easy) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(4,"arguments cipherText, nonce, publicKey and secretKey must be buffers");

    GET_ARG_AS_UCHAR(0, cipherText);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, publicKey, crypto_box_PUBLICKEYBYTES);
    GET_ARG_AS_UCHAR_LEN(3, secretKey, crypto_box_SECRETKEYBYTES);

    // cipherText should have crypto_box_MACBYTES + encrypted message chars so lets check
    if (cipherText_size < crypto_box_MACBYTES) {
        std::ostringstream oss;
        oss << "argument cipherText must have a length of at least " << crypto_box_MACBYTES << " bytes";
        return Nan::ThrowError(oss.str().c_str());
    }

    NEW_BUFFER_AND_PTR(msg, cipherText_size - crypto_box_MACBYTES);

    if( crypto_box_open_easy(msg_ptr, cipherText, cipherText_size, nonce, publicKey, secretKey) == 0) {
        return info.GetReturnValue().Set(msg);
    } else {
        return;
    }
}

/**
 * Partially performs the computation required for both encryption and decryption of data.
 *
 * int crypto_box_beforenm(
 *    unsigned char*        k,
 *    const unsigned char*  pk,
 *    const unsigned char*  sk)
 *
 * Parameters:
 *    [out] k   the result of the computation.
 *    [in]  pk  the receivers public key, used for encryption.
 *    [in]  sk  the senders private key, used for signing.
 *
 * The intermediate data computed by crypto_box_beforenm is suitable for both
 * crypto_box_afternm and crypto_box_open_afternm, and can be reused for any
 * number of messages.
 */
NAN_METHOD(bind_crypto_box_beforenm) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments publicKey, and secretKey must be buffers");

    GET_ARG_AS_UCHAR_LEN(0, publicKey, crypto_box_PUBLICKEYBYTES);
    GET_ARG_AS_UCHAR_LEN(1, secretKey, crypto_box_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(k, crypto_box_BEFORENMBYTES);

    if( crypto_box_beforenm(k_ptr, publicKey, secretKey) != 0) {
      return Nan::ThrowError("crypto_box_beforenm failed");
    }

    return info.GetReturnValue().Set(k);
}

/**
 * Encrypts a given a message m, using partial computed data.
 *
 * int crypto_box_afternm(
 *    unsigned char * ctxt,
 *       const unsigned char * msg,
 *       unsigned long long mlen,
 *       const unsigned char * nonce,
 *       const unsigned char * k)
 *
 * Parameters:
 *    [out] ctxt   the buffer for the cipher-text.
 *    [in]  msg    the message to be encrypted.
 *    [in]  mlen   the length of msg.
 *    [in]  nonce  a randomly generated nonce.
 *    [in]  k      the partial computed data.
 *
 * Returns:
 *    0 if operation is successful.
 */
NAN_METHOD(bind_crypto_box_afternm) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments message, nonce and k must be buffers");

    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, k, crypto_box_BEFORENMBYTES);

    // Pad the message with crypto_box_ZEROBYTES zeros
    NEW_BUFFER_AND_PTR(msg, message_size + crypto_box_ZEROBYTES);

    unsigned int i;
    for(i = 0; i < crypto_box_ZEROBYTES; i++) {
       msg_ptr[i] = 0U;
    }

    //Copy the message to the new buffer
    memcpy((void*) (msg_ptr + crypto_box_ZEROBYTES), (void *) message, message_size);
    message_size += crypto_box_ZEROBYTES;

    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if (crypto_box_afternm(ctxt_ptr, msg_ptr, message_size, nonce, k) == 0) {
        return info.GetReturnValue().Set(ctxt);
    } else {
        return;
    }
}

/**
 * Decrypts a ciphertext ctxt given the receivers private key, and senders public key.
 *
 * int crypto_box_open_afternm ( unsigned char * msg,
 *    const unsigned char * ctxt,
 *    unsigned long long clen,
 *    const unsigned char * nonce,
 *    const unsigned char * k)
 *
 * Parameters:
 *    [out] msg    the buffer to place resulting plaintext.
 *    [in]  ctxt   the ciphertext to be decrypted.
 *    [in]  clen   the length of the ciphertext.
 *    [in]  nonce  a randomly generated nonce.
 *    [in]  k      the partial computed data.
 *
 * Returns:
 *    0 if successful and -1 if verification fails.
 *
 * Precondition:
 *    first crypto_box_BOXZEROBYTES of ctxt be all 0.
 *    the nonce must have size crypto_box_NONCEBYTES.
 *
 * Postcondition:
 *    first clen bytes of msg will contain the plaintext.
 *    first crypto_box_ZEROBYTES of msg will be all 0.
 */
NAN_METHOD(bind_crypto_box_open_afternm) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments cipherText, nonce, k");

    GET_ARG_AS_UCHAR(0, cipherText);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, k, crypto_box_BEFORENMBYTES);

    // API requires that the first crypto_box_BOXZEROBYTES of msg be 0 so lets check
    if (cipherText_size < crypto_box_BOXZEROBYTES) {
        std::ostringstream oss;
        oss << "argument cipherText must have a length of at least " << crypto_box_BOXZEROBYTES << " bytes";
        return Nan::ThrowError(oss.str().c_str());
    }

    unsigned int i;
    for(i = 0; i < crypto_box_BOXZEROBYTES; i++) {
        if( cipherText[i] ) break;
    }

    if (i < crypto_box_BOXZEROBYTES) {
        std::ostringstream oss;
        oss << "the first " << crypto_box_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        return Nan::ThrowError(oss.str().c_str());
    }

    NEW_BUFFER_AND_PTR(msg, cipherText_size);

    if (crypto_box_open_afternm(msg_ptr, cipherText, cipherText_size, nonce, k) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text,cipherText_size - crypto_box_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (msg_ptr + crypto_box_ZEROBYTES), cipherText_size - crypto_box_ZEROBYTES);

        return info.GetReturnValue().Set(plain_text);
    } else {
        return;
    }
}

/**
 * int crypto_scalarmult_base(unsigned char *q, const unsigned char *n)
 */
NAN_METHOD(bind_crypto_scalarmult_base) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument must be a buffer");

    GET_ARG_AS_UCHAR_LEN(0, n, crypto_scalarmult_SCALARBYTES);
    NEW_BUFFER_AND_PTR(q, crypto_scalarmult_BYTES);

    if (crypto_scalarmult_base(q_ptr, n) == 0) {
        return info.GetReturnValue().Set(q);
    } else {
        return;
    }
}


/**
 * int crypto_scalarmult(unsigned char *q, const unsigned char *n,
 *                  const unsigned char *p)
 */
NAN_METHOD(bind_crypto_scalarmult) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments must be buffers");

    GET_ARG_AS_UCHAR_LEN(0, n, crypto_scalarmult_SCALARBYTES);
    GET_ARG_AS_UCHAR_LEN(1, p, crypto_scalarmult_BYTES);

    NEW_BUFFER_AND_PTR(q, crypto_scalarmult_BYTES);

    if (crypto_scalarmult(q_ptr, n, p) == 0) {
        return info.GetReturnValue().Set(q);
    } else {
        return;
    }
}

void RegisterModule(Handle<Object> target) {
    // init sodium library before we do anything
    if( sodium_init() == -1 ) {
        return Nan::ThrowError("libsodium cannot be initialized!");
    }

    randombytes_stir();
    
    register_helpers(target);
    register_randombytes(target);
    register_crypto_pwhash(target);
    register_crypto_hash(target);
    register_crypto_hash_sha256(target);
    register_crypto_hash_sha512(target);
    register_crypto_shorthash(target);
    register_crypto_shorthash_siphash24(target);
    register_crypto_generichash(target);
    
    // Auth
    NEW_METHOD(crypto_auth);
    NEW_METHOD(crypto_auth_verify);
    NEW_INT_PROP(crypto_auth_BYTES);
    NEW_INT_PROP(crypto_auth_KEYBYTES);
    NEW_STRING_PROP(crypto_auth_PRIMITIVE);

    // One Time Auth
    NEW_METHOD(crypto_onetimeauth);
    NEW_METHOD(crypto_onetimeauth_verify);
    NEW_INT_PROP(crypto_onetimeauth_BYTES);
    NEW_INT_PROP(crypto_onetimeauth_KEYBYTES);
    NEW_STRING_PROP(crypto_onetimeauth_PRIMITIVE);

    // Stream
    NEW_METHOD(crypto_stream);
    NEW_METHOD(crypto_stream_xor);
    NEW_INT_PROP(crypto_stream_KEYBYTES);
    NEW_INT_PROP(crypto_stream_NONCEBYTES);
    NEW_STRING_PROP(crypto_stream_PRIMITIVE);

    // Secret Box
    NEW_METHOD(crypto_secretbox);
    NEW_METHOD(crypto_secretbox_open);
    NEW_METHOD(crypto_secretbox_easy);
    NEW_METHOD(crypto_secretbox_open_easy);
    NEW_INT_PROP(crypto_secretbox_BOXZEROBYTES);
    NEW_INT_PROP(crypto_secretbox_MACBYTES);
    NEW_INT_PROP(crypto_secretbox_KEYBYTES);
    NEW_INT_PROP(crypto_secretbox_NONCEBYTES);
    NEW_INT_PROP(crypto_secretbox_ZEROBYTES);
    NEW_STRING_PROP(crypto_secretbox_PRIMITIVE);

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

    // Box
    NEW_METHOD(crypto_box);
    NEW_METHOD(crypto_box_easy);
    NEW_METHOD(crypto_box_keypair);
    NEW_METHOD(crypto_box_open);
    NEW_METHOD(crypto_box_open_easy);
    NEW_METHOD(crypto_box_beforenm);
    NEW_METHOD(crypto_box_afternm);
    NEW_METHOD(crypto_box_open_afternm);
    NEW_INT_PROP(crypto_box_NONCEBYTES);
    NEW_INT_PROP(crypto_box_MACBYTES);
    NEW_INT_PROP(crypto_box_BEFORENMBYTES);
    NEW_INT_PROP(crypto_box_BOXZEROBYTES);
    NEW_INT_PROP(crypto_box_PUBLICKEYBYTES);
    NEW_INT_PROP(crypto_box_SECRETKEYBYTES);
    NEW_INT_PROP(crypto_box_ZEROBYTES);
    NEW_INT_PROP(crypto_box_SEEDBYTES);
    NEW_INT_PROP(crypto_box_SEALBYTES);
    NEW_STRING_PROP(crypto_box_PRIMITIVE);

    // Scalar Mult
    NEW_METHOD(crypto_scalarmult);
    NEW_METHOD(crypto_scalarmult_base);
    NEW_INT_PROP(crypto_scalarmult_SCALARBYTES);
    NEW_INT_PROP(crypto_scalarmult_BYTES);
    NEW_STRING_PROP(crypto_scalarmult_PRIMITIVE);

}

NODE_MODULE(sodium, RegisterModule);