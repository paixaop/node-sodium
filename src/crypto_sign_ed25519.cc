/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"


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
NAPI_METHOD(crypto_sign_ed25519_pk_to_curve25519) {
    Napi::Env env = info.Env();

    ARGS(1, "argument ed25519_pk must be a buffer")
    ARG_TO_UCHAR_BUFFER_LEN(ed25519_pk, crypto_sign_ed25519_PUBLICKEYBYTES);
    
    NEW_BUFFER_AND_PTR(curve25519_pk, crypto_box_PUBLICKEYBYTES);

    if( crypto_sign_ed25519_pk_to_curve25519(curve25519_pk_ptr, ed25519_pk) != 0) {
      Napi::Error::New(env, "crypto_sign_ed25519_pk_to_curve25519 conversion failed").ThrowAsJavaScriptException();
      return NAPI_NULL;
    }

    return curve25519_pk;
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
NAPI_METHOD(crypto_sign_ed25519_sk_to_curve25519) {
    Napi::Env env = info.Env();

    ARGS(1, "argument ed25519_sk must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(ed25519_sk, crypto_sign_ed25519_SECRETKEYBYTES);
    
    NEW_BUFFER_AND_PTR(curve25519_sk, crypto_scalarmult_curve25519_BYTES);

    if( crypto_sign_ed25519_sk_to_curve25519(curve25519_sk_ptr, ed25519_sk) != 0) {
      Napi::Error::New(env, "crypto_sign_ed25519_sk_to_curve25519 conversion failed").ThrowAsJavaScriptException();
      return NAPI_NULL;
    }
    
    return curve25519_sk;
}

/* int crypto_sign_ed25519(unsigned char *sm, unsigned long long *smlen_p,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *sk);
*/
NAPI_METHOD(crypto_sign_ed25519) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments message, and secretKey must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(secretKey, crypto_sign_ed25519_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(sig, message_size + crypto_sign_ed25519_BYTES);

    unsigned long long slen = 0;

    if (crypto_sign_ed25519(sig_ptr, &slen, message, message_size, secretKey) == 0) {
        return sig;
    }
    
    return NAPI_NULL;
}

/* int crypto_sign_ed25519_open(unsigned char *m, unsigned long long *mlen_p,
                             const unsigned char *sm, unsigned long long smlen,
                             const unsigned char *pk)
*/
NAPI_METHOD(crypto_sign_ed25519_open) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments signedMessage and verificationKey must be buffers");
    ARG_TO_UCHAR_BUFFER(signedMessage);
    ARG_TO_UCHAR_BUFFER_LEN(publicKey, crypto_sign_ed25519_PUBLICKEYBYTES);

    unsigned long long mlen = 0;
    NEW_BUFFER_AND_PTR(msg, signedMessage_size);

    if (crypto_sign_ed25519_open(msg_ptr, &mlen, signedMessage, signedMessage_size, publicKey) == 0) {
        NEW_BUFFER_AND_PTR(m, mlen);
        memcpy(m_ptr, msg_ptr, mlen);

        return m;
    } 
    
    return NAPI_NULL;
}

/* int crypto_sign_ed25519_detached(unsigned char *sig,
                                 unsigned long long *siglen_p,
                                 const unsigned char *m,
                                 unsigned long long mlen,
                                 const unsigned char *sk);
*/
NAPI_METHOD(crypto_sign_ed25519_detached) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments message, and secretKey must be buffers");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(secretKey, crypto_sign_ed25519_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(sig, crypto_sign_ed25519_BYTES);

    unsigned long long slen = 0;

    if (crypto_sign_ed25519_detached(sig_ptr, &slen, message, message_size, secretKey) == 0) {
        return sig;
    }
        
    return NAPI_NULL;
}

/* int crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                        const unsigned char *m,
                                        unsigned long long mlen,
                                        const unsigned char *pk)
*/
NAPI_METHOD(crypto_sign_ed25519_verify_detached) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments signedMessage and verificationKey must be buffers");
    ARG_TO_UCHAR_BUFFER_LEN(signature, crypto_sign_ed25519_BYTES);
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(publicKey, crypto_sign_ed25519_PUBLICKEYBYTES);

    if (crypto_sign_ed25519_verify_detached(signature, message, message_size, publicKey) == 0) {
        return NAPI_TRUE;
    }
    
    return NAPI_FALSE;
}

/* int crypto_sign_ed25519_keypair(unsigned char *pk, unsigned char *sk);
 */
NAPI_METHOD(crypto_sign_ed25519_keypair) {
    Napi::Env env = info.Env();

    NEW_BUFFER_AND_PTR(vk, crypto_sign_ed25519_PUBLICKEYBYTES);
    NEW_BUFFER_AND_PTR(sk, crypto_sign_ed25519_SECRETKEYBYTES);

    if (crypto_sign_ed25519_keypair(vk_ptr, sk_ptr) == 0) {
        Napi::Object result = Napi::Object::New(env);
        result.Set(Napi::String::New(env, "publicKey"), vk);
        result.Set(Napi::String::New(env, "secretKey"), sk);

        return result;
    }
    
    return NAPI_NULL;
}

/* crypto_sign_ed25519_seed_keypair(unsigned char *pk, unsigned char *sk,
                                     const unsigned char *seed);
*/
NAPI_METHOD(crypto_sign_ed25519_seed_keypair) {
    Napi::Env env = info.Env();

    ARGS(1, "the argument seed must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(sd, crypto_sign_ed25519_SEEDBYTES);

    NEW_BUFFER_AND_PTR(vk, crypto_sign_ed25519_PUBLICKEYBYTES);
    NEW_BUFFER_AND_PTR(sk, crypto_sign_ed25519_SECRETKEYBYTES);

    if (crypto_sign_ed25519_seed_keypair(vk_ptr, sk_ptr, sd) == 0) {
        Napi::Object result = Napi::Object::New(env);

        result.Set(Napi::String::New(env, "publicKey"), vk);
        result.Set(Napi::String::New(env, "secretKey"), sk);

        return result;
    }
    
    return NAPI_NULL;
}

/* int crypto_sign_ed25519_sk_to_seed(unsigned char *seed,
                                   const unsigned char *sk);
*/
NAPI_METHOD(crypto_sign_ed25519_sk_to_seed) {
    Napi::Env env = info.Env();

    ARGS(1, "the argument seed must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(sk, crypto_sign_ed25519_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(seed, crypto_sign_ed25519_SEEDBYTES);

    if (crypto_sign_ed25519_sk_to_seed(seed_ptr, sk) == 0) {
        return seed;
    }
    
    return NAPI_NULL;
}


/* int crypto_sign_ed25519_sk_to_pk(unsigned char *pk, const unsigned char *sk);
*/
NAPI_METHOD(crypto_sign_ed25519_sk_to_pk) {
    Napi::Env env = info.Env();

    ARGS(1, "the argument seed must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(sk, crypto_sign_ed25519_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(pk, crypto_sign_ed25519_PUBLICKEYBYTES);

    if (crypto_sign_ed25519_sk_to_pk(pk_ptr, sk) == 0) {
        return pk;
    }
    
    return NAPI_NULL;
}


/**
 * Register function calls in node binding
 */
void register_crypto_sign_ed25519(Napi::Env env, Napi::Object exports) {
    
    EXPORT(crypto_sign_ed25519);
    EXPORT(crypto_sign_ed25519_open);
    EXPORT(crypto_sign_ed25519_detached);
    EXPORT(crypto_sign_ed25519_verify_detached);
    EXPORT(crypto_sign_ed25519_keypair);
    EXPORT(crypto_sign_ed25519_seed_keypair);
    EXPORT(crypto_sign_ed25519_pk_to_curve25519);
    EXPORT(crypto_sign_ed25519_sk_to_curve25519);
    EXPORT(crypto_sign_ed25519_sk_to_seed);
    EXPORT(crypto_sign_ed25519_sk_to_pk);
    
    EXPORT_INT(crypto_sign_ed25519_PUBLICKEYBYTES);
    EXPORT_INT(crypto_sign_ed25519_SECRETKEYBYTES);
    EXPORT_INT(crypto_sign_ed25519_BYTES);
    EXPORT_INT(crypto_sign_ed25519_SEEDBYTES);
}
