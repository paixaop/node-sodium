/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

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
NAPI_METHOD(crypto_box) {
    Napi::Env env = info.Env();

    ARGS(4, "arguments message, nonce, publicKey and secretKey must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_box_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(publicKey, crypto_box_PUBLICKEYBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(secretKey, crypto_box_SECRETKEYBYTES);

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
        return ctxt;
    }

    return NAPI_NULL;
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
NAPI_METHOD(crypto_box_easy) {
    Napi::Env env = info.Env();

    ARGS(4, "arguments message, nonce, publicKey and secretKey must be buffers");
    ARG_TO_UCHAR_BUFFER_OR_NULL(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_box_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(publicKey, crypto_box_PUBLICKEYBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(secretKey, crypto_box_SECRETKEYBYTES);

    // The ciphertext will include the mac.
    NEW_BUFFER_AND_PTR(ctxt, message_size + crypto_box_MACBYTES);

    if (crypto_box_easy(ctxt_ptr, message, message_size, nonce, publicKey, secretKey) == 0) {
        return ctxt;
    } 

    return NAPI_NULL;
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
NAPI_METHOD(crypto_box_keypair) {
    Napi::Env env = info.Env();

    NEW_BUFFER_AND_PTR(pk, crypto_box_PUBLICKEYBYTES);
    NEW_BUFFER_AND_PTR(sk, crypto_box_SECRETKEYBYTES);

    if (crypto_box_keypair(pk_ptr, sk_ptr) == 0) {
        Napi::Object result = Napi::Object::New(env);

        result.Set(Napi::String::New(env, "publicKey"), pk);
        result.Set(Napi::String::New(env, "secretKey"), sk);

        return result;
    }
    
    return NAPI_NULL;
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
NAPI_METHOD(crypto_box_open) {
    Napi::Env env = info.Env();

    ARGS(4, "arguments cipherText, nonce, publicKey and secretKey must be buffers");
    ARG_TO_UCHAR_BUFFER(cipherText);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_box_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(publicKey, crypto_box_PUBLICKEYBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(secretKey, crypto_box_SECRETKEYBYTES);

    // API requires that the first crypto_box_BOXZEROBYTES of msg be 0 so lets check
    if (cipherText_size < crypto_box_BOXZEROBYTES) {
        THROW_ERROR("argument cipher text must be at least crypto_box_BOXZEROBYTES bytes long");
    }

    unsigned int i;

    for (i = 0; i < crypto_box_BOXZEROBYTES; i++) {
        if( cipherText[i] ) break;
    }

    if (i < crypto_box_BOXZEROBYTES) {
        THROW_ERROR("the first crypto_box_BOXZEROBYTES bytes of argument cipherText must be 0");
    }

    NEW_BUFFER_AND_PTR(msg, cipherText_size);

    if (crypto_box_open(msg_ptr, cipherText, cipherText_size, nonce, publicKey, secretKey) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text, cipherText_size - crypto_box_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (msg_ptr + crypto_box_ZEROBYTES), cipherText_size - crypto_box_ZEROBYTES);

        return plain_text;
    } 
    
    return NAPI_NULL;
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
NAPI_METHOD(crypto_box_open_easy) {
    Napi::Env env = info.Env();

    ARGS(4, "arguments cipherText, nonce, publicKey and secretKey must be buffers");
    ARG_TO_UCHAR_BUFFER(cipherText);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_box_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(publicKey, crypto_box_PUBLICKEYBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(secretKey, crypto_box_SECRETKEYBYTES);

    // cipherText should have crypto_box_MACBYTES + encrypted message chars so lets check
    if (cipherText_size < crypto_box_MACBYTES) {
        THROW_ERROR("argument cipherText must have a length of at least crypto_box_MACBYTES bytes");
    }

    NEW_BUFFER_AND_PTR(msg, cipherText_size - crypto_box_MACBYTES);

    if( crypto_box_open_easy(msg_ptr, cipherText, cipherText_size, nonce, publicKey, secretKey) == 0) {
        return msg;
    } 
    
    return NAPI_NULL;
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
NAPI_METHOD(crypto_box_beforenm) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments publicKey, and secretKey must be buffers");
    ARG_TO_UCHAR_BUFFER_LEN(publicKey, crypto_box_PUBLICKEYBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(secretKey, crypto_box_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(k, crypto_box_BEFORENMBYTES);

    if( crypto_box_beforenm(k_ptr, publicKey, secretKey) == 0) {
        return k;
    }

    return NAPI_NULL;
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
NAPI_METHOD(crypto_box_afternm) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments message, nonce and k must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_box_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(k, crypto_box_BEFORENMBYTES);

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
        return ctxt;
    } 
    
    return NAPI_NULL;
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
NAPI_METHOD(crypto_box_open_afternm) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments cipherText, nonce, k");
    ARG_TO_UCHAR_BUFFER(cipherText);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_box_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(k, crypto_box_BEFORENMBYTES);

    // API requires that the first crypto_box_BOXZEROBYTES of msg be 0 so lets check
    if (cipherText_size < crypto_box_BOXZEROBYTES) {
        THROW_ERROR("argument cipherText must have a length of at least crypto_box_BOXZEROBYTES bytes");
    }

    unsigned int i;
    for(i = 0; i < crypto_box_BOXZEROBYTES; i++) {
        if( cipherText[i] ) break;
    }

    if (i < crypto_box_BOXZEROBYTES) {
        THROW_ERROR("the first crypto_box_BOXZEROBYTES bytes of argument cipherText must be 0");
    }

    NEW_BUFFER_AND_PTR(msg, cipherText_size);

    if (crypto_box_open_afternm(msg_ptr, cipherText, cipherText_size, nonce, k) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text,cipherText_size - crypto_box_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (msg_ptr + crypto_box_ZEROBYTES), cipherText_size - crypto_box_ZEROBYTES);

        return plain_text;
    }
        
    return NAPI_NULL;
}

/*
int crypto_box_detached(unsigned char *c,
                        unsigned char *mac,
                        const unsigned char *m,
                        unsigned long long mlen,
                        const unsigned char *n,
                        const unsigned char *pk,
                        const unsigned char *sk)
*/
NAPI_METHOD(crypto_box_detached) {
    Napi::Env env = info.Env();

    ARGS(4, "arguments mac, message, nonce, and public and private key must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_secretbox_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(pk, crypto_box_PUBLICKEYBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(sk, crypto_box_SECRETKEYBYTES);
    
    NEW_BUFFER_AND_PTR(c, message_size);
    NEW_BUFFER_AND_PTR(mac, crypto_secretbox_MACBYTES);

    if (crypto_box_detached(c_ptr, mac_ptr, message, message_size, nonce, pk, sk) == 0) {
        Napi::Object result = Napi::Object::New(env);
        result.Set(Napi::String::New(env, "cipherText"), c);
        result.Set(Napi::String::New(env, "mac"), mac);
        return result;
    }
    
    return NAPI_NULL;
}

/*
 *int crypto_box_open_detached(unsigned char *m,
 *                           const unsigned char *c,
                             const unsigned char *mac,
                             unsigned long long clen,
                             const unsigned char *n,
                             const unsigned char *pk,
                             const unsigned char *sk)

 */
NAPI_METHOD(crypto_box_open_detached) {
    Napi::Env env = info.Env();

    ARGS(5, "arguments encrypted message, mac, nonce, and key must be buffers");
    ARG_TO_UCHAR_BUFFER(c);
    ARG_TO_UCHAR_BUFFER_LEN(mac, crypto_secretbox_MACBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_secretbox_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(pk, crypto_box_PUBLICKEYBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(sk, crypto_box_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(m, c_size);

    if (crypto_box_open_detached(m_ptr, c, mac, c_size, nonce, pk, sk) == 0) {
        return m;
    }
    
    return NAPI_NULL;
}

/*
 *int crypto_box_seal(unsigned char *c, const unsigned char *m,
                    unsigned long long mlen, const unsigned char *pk);
 */
NAPI_METHOD(crypto_box_seal) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments unencrypted message, and recipient public key must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(pk, crypto_box_PUBLICKEYBYTES);

    NEW_BUFFER_AND_PTR(c, message_size + crypto_box_SEALBYTES);

    if (crypto_box_seal(c_ptr, message, message_size, pk) == 0) {
        return c;
    }
    
    return NAPI_NULL;
}

/*
 *int crypto_box_seal_open(unsigned char *m, const unsigned char *c,
                         unsigned long long clen,
                         const unsigned char *pk, const unsigned char *sk)
 */
NAPI_METHOD(crypto_box_seal_open) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments encrypted message, recipient public key, and recipient secret key must be buffers");
    ARG_TO_UCHAR_BUFFER(c);
    ARG_TO_UCHAR_BUFFER_LEN(pk, crypto_box_PUBLICKEYBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(sk, crypto_box_SECRETKEYBYTES);
    
    NEW_BUFFER_AND_PTR(m, c_size - crypto_box_SEALBYTES);

    if (crypto_box_seal_open(m_ptr, c, c_size, pk, sk) == 0) {
        return m;
    }
    
    return NAPI_NULL;
}

/*
 *int crypto_box_seed_keypair(unsigned char *pk, unsigned char *sk,
                            const unsigned char *seed);
 */
NAPI_METHOD(crypto_box_seed_keypair) {
    Napi::Env env = info.Env();

    ARGS(1, "argument seed must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(seed, crypto_box_SEEDBYTES);
    
    NEW_BUFFER_AND_PTR(pk, crypto_box_PUBLICKEYBYTES);
    NEW_BUFFER_AND_PTR(sk, crypto_box_SECRETKEYBYTES);

    if (crypto_box_seed_keypair(pk_ptr, sk_ptr, seed) == 0) {
        Napi::Object result = Napi::Object::New(env);

        result.Set(Napi::String::New(env, "publicKey"), pk);
        result.Set(Napi::String::New(env, "secretKey"), sk);

        return result;
    }
    
    return NAPI_NULL;
}

/*
int crypto_box_detached_afternm(unsigned char *c, unsigned char *mac,
                                const unsigned char *m, unsigned long long mlen,
                                const unsigned char *n, const unsigned char *k);
*/
NAPI_METHOD(crypto_box_detached_afternm) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments message, nonce and k must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_box_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(k, crypto_box_BEFORENMBYTES);

    // Pad the message with crypto_box_ZEROBYTES zeros
    NEW_BUFFER_AND_PTR(c, message_size);
    NEW_BUFFER_AND_PTR(mac, crypto_secretbox_MACBYTES);

    if (crypto_box_detached_afternm(c_ptr, mac_ptr, message, message_size, nonce, k) == 0) {
        Napi::Object result = Napi::Object::New(env);
        result.Set(Napi::String::New(env, "cipherText"), c);
        result.Set(Napi::String::New(env, "mac"), mac);
        return result;
    }
    
    return NAPI_NULL;   
}

/*
int crypto_box_open_detached_afternm(unsigned char *m, const unsigned char *c,
                                     const unsigned char *mac,
                                     unsigned long long clen, const unsigned char *n,
                                     const unsigned char *k)
*/
NAPI_METHOD(crypto_box_open_detached_afternm) {
    Napi::Env env = info.Env();

    ARGS(4, "arguments message, nonce and k must be buffers");
    ARG_TO_UCHAR_BUFFER(ctxt);
    ARG_TO_UCHAR_BUFFER_LEN(mac, crypto_box_MACBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_box_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(k, crypto_box_BEFORENMBYTES);

    // Pad the message with crypto_box_ZEROBYTES zeros
    NEW_BUFFER_AND_PTR(message, ctxt_size);

    if (crypto_box_open_detached_afternm(message_ptr, ctxt, mac, ctxt_size, nonce, k) == 0) {
        return message;
    }
    
    return NAPI_NULL;   
}

/*
 int crypto_box_easy_afternm(unsigned char *c, const unsigned char *m,
                            unsigned long long mlen, const unsigned char *n,
                            const unsigned char *k);
*/
NAPI_METHOD(crypto_box_easy_afternm) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments message, nonce and k must be buffers");
    ARG_TO_UCHAR_BUFFER_OR_NULL(message);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_box_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(k, crypto_box_BEFORENMBYTES);

    // The ciphertext will include the mac.
    NEW_BUFFER_AND_PTR(ctxt, crypto_box_MACBYTES + message_size);

    if (crypto_box_easy_afternm(ctxt_ptr, message, message_size, nonce, k) == 0) {
        return ctxt;
    }
    
    return NAPI_NULL;   
}

/*
int crypto_box_open_easy_afternm(unsigned char *m, const unsigned char *c,
                                 unsigned long long clen, const unsigned char *n,
                                 const unsigned char *k)
*/
NAPI_METHOD(crypto_box_open_easy_afternm) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments message, nonce and k must be buffers");
    ARG_TO_UCHAR_BUFFER(ctxt);
    ARG_TO_UCHAR_BUFFER_LEN(nonce, crypto_box_NONCEBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(k, crypto_box_BEFORENMBYTES);

    // cipherText should have crypto_box_MACBYTES + encrypted message chars so lets check
    if (ctxt_size < crypto_box_MACBYTES) {
        THROW_ERROR("argument cipherText must have a length of at least crypto_box_MACBYTES bytes");
    }

    NEW_BUFFER_AND_PTR(message, ctxt_size - crypto_box_MACBYTES);

    if (crypto_box_open_easy_afternm(message_ptr, ctxt, ctxt_size, nonce, k) == 0) {
        return message;
    }
    
    return NAPI_NULL;   
}

NAPI_METHOD_FROM_INT(crypto_box_noncebytes)
NAPI_METHOD_FROM_INT(crypto_box_macbytes)
NAPI_METHOD_FROM_INT(crypto_box_beforenmbytes)
NAPI_METHOD_FROM_INT(crypto_box_boxzerobytes)
NAPI_METHOD_FROM_INT(crypto_box_publickeybytes)
NAPI_METHOD_FROM_INT(crypto_box_secretkeybytes)
NAPI_METHOD_FROM_INT(crypto_box_zerobytes)
NAPI_METHOD_FROM_INT(crypto_box_seedbytes)
NAPI_METHOD_FROM_INT(crypto_box_sealbytes)
NAPI_METHOD_FROM_INT(crypto_box_messagebytes_max)
NAPI_METHOD_FROM_STRING(crypto_box_primitive)

/**
 * Register function calls in node binding
 */
void register_crypto_box(Napi::Env env, Napi::Object exports) {

     // Box
    EXPORT(crypto_box);
    EXPORT(crypto_box_keypair);
    
    EXPORT(crypto_box_easy);
    EXPORT(crypto_box_easy_afternm);
    
    EXPORT(crypto_box_beforenm);
    EXPORT(crypto_box_afternm);
    EXPORT(crypto_box_seed_keypair);
    
    EXPORT(crypto_box_detached);
    EXPORT(crypto_box_detached_afternm);
    
    EXPORT(crypto_box_open);
    EXPORT(crypto_box_open_afternm);
    EXPORT(crypto_box_open_easy);
    EXPORT(crypto_box_open_detached);
    EXPORT(crypto_box_open_detached_afternm);
    EXPORT(crypto_box_open_easy_afternm);
    
    EXPORT(crypto_box_seal);
    EXPORT(crypto_box_seal_open);
    
    EXPORT_INT(crypto_box_NONCEBYTES);
    EXPORT_INT(crypto_box_MACBYTES);
    EXPORT_INT(crypto_box_BEFORENMBYTES);
    EXPORT_INT(crypto_box_BOXZEROBYTES);
    EXPORT_INT(crypto_box_PUBLICKEYBYTES);
    EXPORT_INT(crypto_box_SECRETKEYBYTES);
    EXPORT_INT(crypto_box_ZEROBYTES);
    EXPORT_INT(crypto_box_SEEDBYTES);
    EXPORT_INT(crypto_box_SEALBYTES);
    EXPORT_INT(crypto_box_MESSAGEBYTES_MAX);

    EXPORT(crypto_box_noncebytes);
    EXPORT(crypto_box_macbytes);
    EXPORT(crypto_box_beforenmbytes);
    EXPORT(crypto_box_boxzerobytes);
    EXPORT(crypto_box_publickeybytes);
    EXPORT(crypto_box_secretkeybytes);
    EXPORT(crypto_box_zerobytes);
    EXPORT(crypto_box_seedbytes);
    EXPORT(crypto_box_sealbytes);
    EXPORT(crypto_box_messagebytes_max);

    EXPORT(crypto_box_primitive);
    EXPORT_STRING(crypto_box_PRIMITIVE);
}
