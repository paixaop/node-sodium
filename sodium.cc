/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include <node.h>
#include <node_buffer.h>

#include <cstdlib>
#include <ctime>
#include <string>
#include <sstream>

#include "sodium.h"

using namespace node;
using namespace v8;

// Check if a function argument is a node Buffer. If not throw V8 exception
#define ARG_IS_BUFFER(i,msg) \
    if (!Buffer::HasInstance(args[i])) { \
        std::ostringstream oss; \
        oss << "argument " << msg << " must be a buffer"; \
        return ThrowException(Exception::Error(String::New(oss.str().c_str()))); \
    }

// Check if a function argument has a node Buffer of length len. If not throw V8 exception
#define ARG_CHECK_LENGTH(i, len, msg) \
    if( Buffer::Length(args[i]->ToObject()) != len ) { \
        std::ostringstream oss; \
        oss << "argument " << msg << " must be " << len << " long" ; \
        return ThrowException(Exception::Error(String::New(oss.str().c_str()))); \
    }

// Check if var v is not zero, or throw V8 exception
#define LENGTH_NOT_ZERO(v) \
    if( v == 0 ) { \
        std::ostringstream oss; \
        oss << "argument " << v << " length cannot be zero" ; \
        return ThrowException(Exception::Error(String::New(oss.str().c_str()))); \
    }

// Get a unsigned char pointer to ARG[i] which must be node Buffer
#define ARG_TO_UCHAR_PTR(i) (unsigned char*) Buffer::Data(args[i]->ToObject())

// Get a void pointer to ARG[i] which must be node Buffer
#define ARG_TO_VOID_PTR(i)  (void*) Buffer::Data(args[0]->ToObject())

// Get the node Buffer length of function argument i
#define ARG_LENGTH(i)       Buffer::Length(args[i]->ToObject())

//Helper function
static Handle<Value> V8Exception(const char* msg) {
    return ThrowException(Exception::Error(String::New(msg)));
}

// Lib Sodium Version Functions
Handle<Value> bind_version(const Arguments& args) {
    HandleScope scope;
    return scope.Close(
        String::New(sodium_version_string())
    );
}

Handle<Value> bind_version_minor(const Arguments& args) {
    HandleScope scope;
    return scope.Close(
        Integer::New(sodium_library_version_minor())
    );
}

Handle<Value> bind_version_major(const Arguments& args) {
    HandleScope scope;
    return scope.Close(
        Integer::New(sodium_library_version_major())
    );
}

// Lib Sodium Utils
Handle<Value> bind_memzero(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
        return V8Exception("argument must be a buffer");
    }

    ARG_IS_BUFFER(0,"1");
    void* pnt =  ARG_TO_VOID_PTR(0);
    size_t size = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(size);

    sodium_memzero(pnt, size);
    return scope.Close(Null());
}

// Lib Sodium Random

// void randombytes_buf(void *const buf, const size_t size)
Handle<Value> bind_randombytes_buf(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
        return V8Exception("argument must be a buffer");
    }

    ARG_IS_BUFFER(0,"1");

    void* buf =  ARG_TO_VOID_PTR(0);
    size_t size = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(size);

    randombytes_buf(buf, size);
    return scope.Close(Null());
}

// void randombytes_stir()
Handle<Value> bind_randombytes_stir(const Arguments& args) {
    HandleScope scope;
    randombytes_stir();
    return scope.Close(Null());
}

Handle<Value> bind_randombytes_close(const Arguments& args) {
    HandleScope scope;

    // int randombytes_close()
    return scope.Close(Integer::New(randombytes_close()));
}

Handle<Value> bind_randombytes_random(const Arguments& args) {
    HandleScope scope;

    // uint_32 randombytes_random()
    return scope.Close(Uint32::New(randombytes_random()));
}

Handle<Value> bind_randombytes_uniform(const Arguments& args) {
    HandleScope scope;
    uint32_t upper_bound;

    if (args.Length() < 1) {
        return V8Exception("argument size must be a positive");
    }

    if (args[0]->IsUint32()) {
        upper_bound = args[0]->Int32Value();
    } else {
        return V8Exception("argument size must be a positive number");
    }

    // uint32_t randombytes_uniform(const uint32_t upper_bound)
    return scope.Close(Uint32::New(randombytes_uniform(upper_bound)));
}


Handle<Value> bind_crypto_verify_16(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 2) {
        return V8Exception("arguments must be two buffers");
    }

    ARG_IS_BUFFER(0,"1");
    ARG_IS_BUFFER(1,"2");

    // Get arguments
    unsigned char* string1 = ARG_TO_UCHAR_PTR(0);
    unsigned char* string2 = ARG_TO_UCHAR_PTR(1);

    // Get/Check sizes
    ARG_CHECK_LENGTH(0,crypto_verify_16_BYTES, "1");
    ARG_CHECK_LENGTH(1,crypto_verify_16_BYTES, "2");

    return scope.Close(Integer::New(crypto_verify_16(string1, string2)));
}

// int crypto_verify_16(const unsigned char * string1, const unsigned char * string2)
Handle<Value> bind_crypto_verify_32(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 2) {
        return V8Exception("arguments must be two buffers");
    }

    ARG_IS_BUFFER(0,"1");
    ARG_IS_BUFFER(1,"2");

    // Get arguments
    unsigned char* string1 = ARG_TO_UCHAR_PTR(0);
    unsigned char* string2 = ARG_TO_UCHAR_PTR(1);

    // Get/Check sizes
    ARG_CHECK_LENGTH(0,crypto_verify_32_BYTES, "1");
    ARG_CHECK_LENGTH(1,crypto_verify_32_BYTES, "2");

    return scope.Close(Integer::New(crypto_verify_32(string1, string2)));
}

/**
 * int crypto_hash(
 *    unsigned char * hbuf,
 *    const unsigned char * msg,
 *    unsigned long long mlen)
 */
Handle<Value> bind_crypto_hash(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
        return V8Exception("argument message must be a buffer");
    }

    // Get arguments
    ARG_IS_BUFFER(0,"message");
    unsigned char* msg = ARG_TO_UCHAR_PTR(0);
    unsigned long long mlen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(mlen);

    Buffer* hashBuf = Buffer::New(crypto_hash_BYTES);
    unsigned char* hbuf = (unsigned char*)Buffer::Data(hashBuf);

    if( crypto_hash(hbuf, msg, mlen) == 0 ) {
        return scope.Close(hashBuf->handle_);
    }
    return scope.Close(Null());
}

/**
 * int crypto_hash_sha256(
 *    unsigned char * hbuf,
 *    const unsigned char * msg,
 *    unsigned long long mlen)
 */
Handle<Value> bind_crypto_hash_sha256(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
        return V8Exception("argument message must be a buffer");
    }

    // Get arguments
    ARG_IS_BUFFER(0,"message");
    unsigned char* msg = ARG_TO_UCHAR_PTR(0);
    unsigned long long mlen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(mlen);

    Buffer* hashBuf = Buffer::New(32); // sha256
    unsigned char* hbuf = (unsigned char*)Buffer::Data(hashBuf);

    if( crypto_hash_sha256(hbuf, msg, mlen) == 0 ) {
        return scope.Close(hashBuf->handle_);
    }
    return scope.Close(Null());
}

/**
 * int crypto_hash_sha512(
 *    unsigned char * hbuf,
 *    const unsigned char * msg,
 *    unsigned long long mlen)
 */
Handle<Value> bind_crypto_hash_sha512(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 1) {
        return V8Exception("argument message must be a buffer");
    }

    // Get arguments
    ARG_IS_BUFFER(0,"message");
    unsigned char* msg = ARG_TO_UCHAR_PTR(0);
    unsigned long long mlen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(mlen);

    Buffer* hashBuf = Buffer::New(64);  // sha512
    unsigned char* hbuf = (unsigned char*)Buffer::Data(hashBuf);

    if( crypto_hash_sha512(hbuf, msg, mlen) == 0 ) {
        return scope.Close(hashBuf->handle_);
    }
    return scope.Close(Null());
}


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
Handle<Value> bind_crypto_auth(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 2) {
        return V8Exception("arguments message, and key must be buffers");
    }

    // Get arguments
    ARG_IS_BUFFER(0,"message");
    ARG_IS_BUFFER(1,"key");

    unsigned char* msg = ARG_TO_UCHAR_PTR(0);
    unsigned char* key = ARG_TO_UCHAR_PTR(1);

    // Get/Check sizes
    unsigned long long mlen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(mlen);

    ARG_CHECK_LENGTH(1,crypto_auth_KEYBYTES, "key");

    Buffer* token = Buffer::New(crypto_auth_BYTES);
    unsigned char* tok = (unsigned char*)Buffer::Data(token);

    if( crypto_auth(tok, msg, mlen, key) == 0 ) {
        return scope.Close(token->handle_);
    }
    return scope.Close(Null());
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
Handle<Value> bind_crypto_auth_verify(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 3) {
        return V8Exception("arguments token, message, and key must be buffers");
    }

    // Check that we got buffers
    ARG_IS_BUFFER(0,"token");
    ARG_IS_BUFFER(1,"message");
    ARG_IS_BUFFER(2,"key");

    // Get arguments
    unsigned char* tok = ARG_TO_UCHAR_PTR(0);
    unsigned char* msg = ARG_TO_UCHAR_PTR(1);
    unsigned char* key = ARG_TO_UCHAR_PTR(2);

    // Get/Check sizes
    unsigned long long mlen = ARG_LENGTH(1);
    LENGTH_NOT_ZERO(mlen);

    ARG_CHECK_LENGTH(0,crypto_auth_BYTES, "token");
    ARG_CHECK_LENGTH(2,crypto_auth_KEYBYTES, "key");

    return scope.Close(Integer::New(crypto_auth_verify(tok, msg, mlen, key)));
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
Handle<Value> bind_crypto_onetimeauth(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 2) {
        return V8Exception("arguments message, and key must be buffers");
    }

    // Check that we got buffers
    ARG_IS_BUFFER(0,"message");
    ARG_IS_BUFFER(1,"key");

    // Get arguments
    unsigned char* msg = ARG_TO_UCHAR_PTR(0);
    unsigned char* key = ARG_TO_UCHAR_PTR(1);

    // Get/Check sizes
    unsigned long long mlen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(mlen);

    ARG_CHECK_LENGTH(1,crypto_onetimeauth_KEYBYTES, "key");

    Buffer* token = Buffer::New(crypto_onetimeauth_BYTES);
    unsigned char* tok = (unsigned char*)Buffer::Data(token);

    if( crypto_onetimeauth(tok, msg, mlen, key) == 0 ) {
        return scope.Close(token->handle_);
    }
    return scope.Close(Null());
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
Handle<Value> bind_crypto_onetimeauth_verify(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 3) {
        return V8Exception("arguments token, message, and key must be buffers");
    }

    // Check that we got buffers
    ARG_IS_BUFFER(0,"token");
    ARG_IS_BUFFER(1,"message");
    ARG_IS_BUFFER(2,"key");

    // Get arguments
    unsigned char* tok =  ARG_TO_UCHAR_PTR(0);
    unsigned char* msg =  ARG_TO_UCHAR_PTR(1);
    unsigned char* key =  ARG_TO_UCHAR_PTR(2);

    // Get/Check sizes
    unsigned long long mlen = ARG_LENGTH(1);
    LENGTH_NOT_ZERO(mlen);

    ARG_CHECK_LENGTH(0,crypto_onetimeauth_BYTES, "token");
    ARG_CHECK_LENGTH(2,crypto_onetimeauth_KEYBYTES, "key");

    return scope.Close(Integer::New(crypto_onetimeauth_verify(tok, msg, mlen, key)));
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
 *    [in]  slen    the length of the generated stream.
 *    [in]  nonce   the nonce used to generate the stream.
 *    [in]  key     the key used to generate the stream.
 *
 * Returns:
 *    0 if operation successful
 */
Handle<Value> bind_crypto_stream(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 3) {
        return V8Exception("argument length must be a positive number, arguments nonce, and key must be buffers");
    }

    if (!args[0]->IsUint32())
        return V8Exception("argument length must be positive number");

    //if (args[0]->ToInt32()->Value() <= 0 )
    //    return V8Exception("argument length must be positive number");

    // Check that we got buffers
    ARG_IS_BUFFER(1,"nonce");
    ARG_IS_BUFFER(2,"key");


    // Get arguments
    unsigned long long slen = args[0]->ToUint32()->Value();

    unsigned char* nonce = ARG_TO_UCHAR_PTR(1);
    unsigned char* key = ARG_TO_UCHAR_PTR(2);

    // Get/Check sizes
    ARG_CHECK_LENGTH(1,crypto_stream_NONCEBYTES, "nonce");
    ARG_CHECK_LENGTH(2,crypto_stream_KEYBYTES, "key");

    Buffer* sBuf = Buffer::New(slen);
    unsigned char* stream = (unsigned char*)Buffer::Data(sBuf);

    if( crypto_stream(stream, slen, nonce, key) == 0) {
        return scope.Close(sBuf->handle_);
    }
    return scope.Close(Undefined());
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
Handle<Value> bind_crypto_stream_xor(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 3) {
        return V8Exception("arguments message, nonce, and key must be buffers");
    }

    // Check that we got buffers
    ARG_IS_BUFFER(0,"message");
    ARG_IS_BUFFER(1,"nonce");
    ARG_IS_BUFFER(2,"key");

    // Get arguments
    unsigned char* msg = ARG_TO_UCHAR_PTR(0);
    unsigned char* nonce = ARG_TO_UCHAR_PTR(1);
    unsigned char* key = ARG_TO_UCHAR_PTR(2);

    // Get/Check sizes
    unsigned long long mlen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(mlen);

    ARG_CHECK_LENGTH(1,crypto_stream_NONCEBYTES, "nonce");
    ARG_CHECK_LENGTH(2,crypto_stream_KEYBYTES, "key");

    Buffer* sBuf = Buffer::New(mlen);
    unsigned char* ctx = (unsigned char*)Buffer::Data(sBuf);

    if( crypto_stream_xor(ctx, msg, mlen, nonce, key) == 0) {
        return scope.Close(sBuf->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * TODO
 * int crypto_stream_afternm(
 *    unsigned char *outp,
 *    unsigned long long len,
 *    const unsigned char *noncep,
 *    const unsigned char *c)
 *
 */

/**
 * TODO
 * int crypto_stream_beforenm(
 *    unsigned char *outp,
 *    unsigned long long len,
 *    const unsigned char *noncep,
 *    const unsigned char *c)
 *
 */

/**
 * TODO
 * int crypto_stream_xor_afternm(
 *    unsigned char *,
 *    unsigned char *,
 *    unsigned long long,
 *    const unsigned char *,
 *    const unsigned char *)
 *
 */

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
Handle<Value> bind_crypto_secretbox(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 3) {
        return V8Exception("arguments message, nonce, and key must be buffers");
    }

    // Check that we got buffers
    ARG_IS_BUFFER(0,"message");
    ARG_IS_BUFFER(1,"nonce");
    ARG_IS_BUFFER(2,"key");

    // Get arguments
    unsigned char* msg = ARG_TO_UCHAR_PTR(0);
    unsigned char* nonce = ARG_TO_UCHAR_PTR(1);
    unsigned char* key = ARG_TO_UCHAR_PTR(2);

    // Get/Check sizes
    unsigned long long mlen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(mlen);

    ARG_CHECK_LENGTH(1,crypto_secretbox_NONCEBYTES, "nonce");
    ARG_CHECK_LENGTH(2,crypto_secretbox_KEYBYTES, "key");

    // Pad the message with crypto_secretbox_ZEROBYTES zeros
    Buffer* paddedMessageBuffer = Buffer::New(mlen + crypto_secretbox_ZEROBYTES);
    unsigned char* pmb = (unsigned char*)Buffer::Data(paddedMessageBuffer);

    // Fill the first crypto_secretbox_ZEROBYTES with 0
    unsigned int i;
    for(i=0; i < crypto_secretbox_ZEROBYTES; i++) {
        pmb[i] = 0U;
    }

    //Copy the message to the new buffer
    memcpy((void*) (pmb + crypto_secretbox_ZEROBYTES), (void *) msg, mlen);
    mlen += crypto_secretbox_ZEROBYTES;

    Buffer* sBuf = Buffer::New(mlen);
    unsigned char* ctx = (unsigned char*)Buffer::Data(sBuf);

    if( crypto_secretbox(ctx, pmb, mlen, nonce, key) == 0) {
        return scope.Close(sBuf->handle_);
    }
    return scope.Close(Undefined());
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
Handle<Value> bind_crypto_secretbox_open(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 3) {
        return V8Exception("arguments cipherText, nonce, and key must be buffers");
    }

    // Check that we got buffers
    ARG_IS_BUFFER(0,"cipherText");
    ARG_IS_BUFFER(1,"nonce");
    ARG_IS_BUFFER(2,"key");

    // Get arguments
    unsigned char* ctx = ARG_TO_UCHAR_PTR(0);
    unsigned char* nonce = ARG_TO_UCHAR_PTR(1);
    unsigned char* key = ARG_TO_UCHAR_PTR(2);

    // Get/Check sizes
    unsigned long long clen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(clen);

    ARG_CHECK_LENGTH(1,crypto_secretbox_NONCEBYTES, "nonce");
    ARG_CHECK_LENGTH(2,crypto_secretbox_KEYBYTES, "key");

    Buffer* sBuf = Buffer::New(clen);
    unsigned char* msg = (unsigned char*)Buffer::Data(sBuf);

    // API requires that the first crypto_secretbox_ZEROBYTES of msg be 0 so lets check
    if( clen < crypto_secretbox_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "argument cipherText must have at least " << crypto_secretbox_BOXZEROBYTES << " bytes";
        return V8Exception(oss.str().c_str());
    }

    unsigned int i;
    for(i=0; i < crypto_secretbox_BOXZEROBYTES; i++) {
        if( ctx[i] ) break;
    }
    if( i < crypto_secretbox_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "the first " << crypto_secretbox_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        return V8Exception(oss.str().c_str());
    }

    if( crypto_secretbox_open(msg, ctx, clen, nonce, key) == 0) {

        // Remove the padding at the beginning of the message
        Buffer* plainText = Buffer::New(clen - crypto_secretbox_ZEROBYTES);
        void* pTxt = (void*)Buffer::Data(plainText);
        memcpy(pTxt,(void*) (msg + crypto_secretbox_ZEROBYTES), clen - crypto_secretbox_ZEROBYTES);

        return scope.Close(plainText->handle_);
    }
    return scope.Close(Undefined());
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
Handle<Value> bind_crypto_sign(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 2) {
        return V8Exception("arguments message, and secret must be buffers");
    }

    // Check that we got buffers
    ARG_IS_BUFFER(0,"message");
    ARG_IS_BUFFER(1,"secretKey");

    // Get arguments
    unsigned char* msg = ARG_TO_UCHAR_PTR(0);
    unsigned char* sk = ARG_TO_UCHAR_PTR(1);

    // Get/Check sizes
    unsigned long long mlen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(mlen);

    ARG_CHECK_LENGTH(1,crypto_sign_SECRETKEYBYTES, "secretKey");

    Buffer* sBuf = Buffer::New(mlen + crypto_sign_BYTES);
    unsigned char* sig = (unsigned char*)Buffer::Data(sBuf);

    unsigned long long slen = 0;
    if( crypto_sign(sig, &slen, msg, mlen, sk) == 0) {
        return scope.Close(sBuf->handle_);
    }
    return scope.Close(Undefined());
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
Handle<Value> bind_crypto_sign_keypair(const Arguments& args) {
    HandleScope scope;

    Buffer* vkBuf = Buffer::New(crypto_sign_PUBLICKEYBYTES);
    unsigned char* vk = (unsigned char*)Buffer::Data(vkBuf);

    Buffer* skBuf = Buffer::New(crypto_sign_SECRETKEYBYTES);
    unsigned char* sk = (unsigned char*)Buffer::Data(skBuf);

    if( crypto_sign_keypair(vk, sk) == 0) {
        Local<Object> result = Object::New();
        result->Set(String::NewSymbol("publicKey"),vkBuf->handle_);
        result->Set(String::NewSymbol("secretKey"), skBuf->handle_);
        return scope.Close(result);
    }
    return scope.Close(Undefined());
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
Handle<Value> bind_crypto_sign_open(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 2) {
        return V8Exception("arguments signedMessage and verificationKey must be buffers");
    }

    // Check that we got buffers
    ARG_IS_BUFFER(0,"signedMessage");
    ARG_IS_BUFFER(1,"publicKey");

    // Get arguments
    unsigned char* sig = ARG_TO_UCHAR_PTR(0);
    unsigned char* pk = ARG_TO_UCHAR_PTR(1);

    // Get/Check sizes
    unsigned long long smlen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(smlen);

    ARG_CHECK_LENGTH(1,crypto_sign_PUBLICKEYBYTES, "publicKey");

    unsigned long long mlen = 0;
    Buffer* sBuf = Buffer::New(smlen);
    unsigned char* msg = (unsigned char*)Buffer::Data(sBuf);

    if( crypto_sign_open(msg, &mlen, sig, smlen, pk) == 0) {
        Buffer*  mBuf = Buffer::New(mlen);
        unsigned char* m = (unsigned char*)Buffer::Data(mBuf);
        memcpy(m, msg, mlen);
        return scope.Close(mBuf->handle_);
    }
    return scope.Close(Undefined());
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
Handle<Value> bind_crypto_box(const Arguments& args) {
    HandleScope scope;

    if (args.Length() < 4) {
        return V8Exception("arguments message, nonce, publicKey and privateKey must be buffers");
    }

    // Check that we got buffers
    ARG_IS_BUFFER(0,"message");
    ARG_IS_BUFFER(1,"nonce");
    ARG_IS_BUFFER(2,"publicKey");
    ARG_IS_BUFFER(3,"privateKey");

    // Get arguments
    unsigned char* msg = ARG_TO_UCHAR_PTR(0);
    unsigned char* nonce = ARG_TO_UCHAR_PTR(1);
    unsigned char* pk = ARG_TO_UCHAR_PTR(2);
    unsigned char* sk = ARG_TO_UCHAR_PTR(3);

    // Get/Check sizes
    unsigned long long mlen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(mlen);

    ARG_CHECK_LENGTH(1,crypto_box_NONCEBYTES, "nonce");
    ARG_CHECK_LENGTH(2,crypto_box_PUBLICKEYBYTES, "publicKey");
    ARG_CHECK_LENGTH(3,crypto_box_SECRETKEYBYTES, "privateKey");

    // Pad the message with crypto_box_ZEROBYTES zeros
    Buffer* paddedMessageBuffer = Buffer::New(mlen + crypto_box_ZEROBYTES);
    unsigned char* pmsg = (unsigned char*)Buffer::Data(paddedMessageBuffer);

    // Fill the first crypto_box_ZEROBYTES with 0
    unsigned int i;
    for(i=0; i < crypto_box_ZEROBYTES; i++) {
       pmsg[i] = 0U;
    }
    //Copy the message to the new buffer
    memcpy((void*) (pmsg + crypto_box_ZEROBYTES), (void *) msg, mlen);
    mlen += crypto_box_ZEROBYTES;

    Buffer* sBuf = Buffer::New(mlen);
    unsigned char* ctxt = (unsigned char*)Buffer::Data(sBuf);

    if( crypto_box(ctxt, pmsg, mlen, nonce, pk, sk) == 0) {
        return scope.Close(sBuf->handle_);
    }
    return scope.Close(Undefined());
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
Handle<Value> bind_crypto_box_keypair(const Arguments& args) {
    HandleScope scope;
    
    Buffer* pkBuf = Buffer::New(crypto_box_PUBLICKEYBYTES);
    unsigned char* pk = (unsigned char*)Buffer::Data(pkBuf);
    
    Buffer* skBuf = Buffer::New(crypto_box_SECRETKEYBYTES);
    unsigned char* sk = (unsigned char*)Buffer::Data(skBuf);
    
    if( crypto_box_keypair(pk, sk) == 0) {
        Local<Object> result = Object::New();
        result->Set(String::NewSymbol("publicKey"), pkBuf->handle_);
        result->Set(String::NewSymbol("secretKey"), skBuf->handle_);
        return scope.Close(result);
    }
    return scope.Close(Undefined());
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
Handle<Value> bind_crypto_box_open(const Arguments& args) {
    HandleScope scope;
    
    if (args.Length() < 4) {
        return V8Exception("arguments cipherText, nonce, publicKey and privateKey must be buffers");
    }
    
    
    // Check that we got buffers
    ARG_IS_BUFFER(0,"cipherText");
    ARG_IS_BUFFER(1,"nonce");
    ARG_IS_BUFFER(2,"publicKey");
    ARG_IS_BUFFER(3,"privateKey");
    
    // Get arguments
    unsigned char* ctxt = ARG_TO_UCHAR_PTR(0);
    unsigned char* nonce = ARG_TO_UCHAR_PTR(1);
    unsigned char* pk = ARG_TO_UCHAR_PTR(2);
    unsigned char* sk = ARG_TO_UCHAR_PTR(3);
    
    // Get/Check sizes
    unsigned long long clen = ARG_LENGTH(0);
    LENGTH_NOT_ZERO(clen);
    
    ARG_CHECK_LENGTH(1,crypto_box_NONCEBYTES, "nonce");
    ARG_CHECK_LENGTH(2,crypto_box_PUBLICKEYBYTES, "publicKey");
    ARG_CHECK_LENGTH(3,crypto_box_SECRETKEYBYTES, "privateKey");
    
    // API requires that the first crypto_box_BOXZEROBYTES of msg be 0 so lets check
    if( clen < crypto_box_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "argument cipherText must have a length of at least " << crypto_box_BOXZEROBYTES << " bytes";
        return V8Exception(oss.str().c_str());
    }
    
    unsigned int i;
    for(i=0; i < crypto_box_BOXZEROBYTES; i++) {
        if( ctxt[i] ) break;
    }
    if( i < crypto_box_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "the first " << crypto_box_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        return V8Exception(oss.str().c_str());
    }
    
    Buffer* sBuf = Buffer::New(clen);
    unsigned char* msg = (unsigned char*)Buffer::Data(sBuf);
    
    if( crypto_box_open(msg, ctxt, clen, nonce, pk, sk) == 0) {

        // Remove the padding at the beginning of the message
        Buffer* plainText = Buffer::New(clen - crypto_box_ZEROBYTES);
        void* pTxt = (void*)Buffer::Data(plainText);
        memcpy(pTxt,(void*) (msg + crypto_box_ZEROBYTES), clen - crypto_box_ZEROBYTES);

        return scope.Close(plainText->handle_);
    }
    return scope.Close(Undefined());
}


void RegisterModule(Handle<Object> target) {
    // init sodium library before we do anything
    sodium_init();

    // Register version functions
    NODE_SET_METHOD(target, "version", bind_version);
    NODE_SET_METHOD(target, "version_minor", bind_version_minor);
    NODE_SET_METHOD(target, "version_major", bind_version_major);

    // register utilities
    NODE_SET_METHOD(target, "memzero", bind_memzero);

    // register random utilities
    NODE_SET_METHOD(target, "randombytes_buf", bind_randombytes_buf);
    NODE_SET_METHOD(target, "randombytes_close", bind_randombytes_close);
    NODE_SET_METHOD(target, "randombytes_stir", bind_randombytes_stir);
    NODE_SET_METHOD(target, "randombytes_random", bind_randombytes_random);
    NODE_SET_METHOD(target, "randombytes_uniform", bind_randombytes_uniform);

    // String comparisons
    NODE_SET_METHOD(target, "crypto_verify_16", bind_crypto_verify_16);
    NODE_SET_METHOD(target, "crypto_verify_32", bind_crypto_verify_32);

    // Hash
    NODE_SET_METHOD(target, "crypto_hash", bind_crypto_hash);
    NODE_SET_METHOD(target, "crypto_hash_sha512", bind_crypto_hash_sha512);
    NODE_SET_METHOD(target, "crypto_hash_sha256", bind_crypto_hash_sha256);

    // Auth
    NODE_SET_METHOD(target, "crypto_auth", bind_crypto_auth);
    NODE_SET_METHOD(target, "crypto_auth_verify", bind_crypto_auth_verify);

    // One Time Auth
    NODE_SET_METHOD(target, "crypto_onetimeauth", bind_crypto_onetimeauth);
    NODE_SET_METHOD(target, "crypto_onetimeauth_verify", bind_crypto_onetimeauth_verify);

    // Stream
    NODE_SET_METHOD(target, "crypto_stream", bind_crypto_stream);
    NODE_SET_METHOD(target, "crypto_stream_xor", bind_crypto_stream_xor);

    // Secret Box
    NODE_SET_METHOD(target, "crypto_secretbox", bind_crypto_secretbox);
    NODE_SET_METHOD(target, "crypto_secretbox_open", bind_crypto_secretbox_open);

    // Sign
    NODE_SET_METHOD(target, "crypto_sign", bind_crypto_sign);
    NODE_SET_METHOD(target, "crypto_sign_keypair", bind_crypto_sign_keypair);
    NODE_SET_METHOD(target, "crypto_sign_open", bind_crypto_sign_open);
    
    // Box
    NODE_SET_METHOD(target, "crypto_box", bind_crypto_box);
    NODE_SET_METHOD(target, "crypto_box_keypair", bind_crypto_box_keypair);
    NODE_SET_METHOD(target, "crypto_box_open", bind_crypto_box_open);


    // register constants
    target->Set(String::NewSymbol("crypto_auth_BYTES"), Integer::New(crypto_auth_BYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_auth_KEYBYTES"), Integer::New(crypto_auth_KEYBYTES), ReadOnly);

    target->Set(String::NewSymbol("crypto_box_NONCEBYTES"), Integer::New(crypto_box_NONCEBYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_box_BEFORENMBYTES"), Integer::New(crypto_box_BEFORENMBYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_box_BOXZEROBYTES"), Integer::New(crypto_box_BOXZEROBYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_box_PUBLICKEYBYTES"), Integer::New(crypto_box_PUBLICKEYBYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_box_SECRETKEYBYTES"), Integer::New(crypto_box_SECRETKEYBYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_box_ZEROBYTES"), Integer::New(crypto_box_ZEROBYTES), ReadOnly);

    target->Set(String::NewSymbol("crypto_hash_BYTES"), Integer::New(crypto_hash_BYTES), ReadOnly);

    target->Set(String::NewSymbol("crypto_onetimeauth_BYTES"), Integer::New(crypto_onetimeauth_BYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_onetimeauth_KEYBYTES"), Integer::New(crypto_onetimeauth_KEYBYTES), ReadOnly);

    target->Set(String::NewSymbol("crypto_secretbox_BOXZEROBYTES"), Integer::New(crypto_secretbox_BOXZEROBYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_secretbox_KEYBYTES"), Integer::New(crypto_secretbox_KEYBYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_secretbox_NONCEBYTES"), Integer::New(crypto_secretbox_NONCEBYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_secretbox_ZEROBYTES"), Integer::New(crypto_secretbox_ZEROBYTES), ReadOnly);

    target->Set(String::NewSymbol("crypto_sign_BYTES"), Integer::New(crypto_sign_BYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_sign_PUBLICKEYBYTES"), Integer::New(crypto_sign_PUBLICKEYBYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_sign_SECRETKEYBYTES"), Integer::New(crypto_sign_SECRETKEYBYTES), ReadOnly);

    target->Set(String::NewSymbol("crypto_stream_KEYBYTES"), Integer::New(crypto_stream_KEYBYTES), ReadOnly);
    target->Set(String::NewSymbol("crypto_stream_NONCEBYTES"), Integer::New(crypto_stream_NONCEBYTES), ReadOnly);

}

NODE_MODULE(sodium, RegisterModule);