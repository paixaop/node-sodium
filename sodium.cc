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
#include <cstring>
#include <string>
#include <sstream>

#include "sodium.h"

using namespace node;
using namespace v8;


// get handle to the global object
Local<Object> globalObj = Context::GetCurrent()->Global();

// Retrieve the buffer constructor function 
Local<Function> bufferConstructor = 
       Local<Function>::Cast(globalObj->Get(String::New("Buffer")));
       

// Check if a function argument is a node Buffer. If not throw V8 exception
#define ARG_IS_BUFFER(i,msg) \
    if (!Buffer::HasInstance(args[i])) { \
        std::ostringstream oss; \
        oss << "argument " << msg << " must be a buffer"; \
        return ThrowException(Exception::Error(String::New(oss.str().c_str()))); \
    }

// Create a new buffer, and get a pointer to it
#define NEW_BUFFER_AND_PTR(name, size) \
    Buffer* name = Buffer::New(size); \
    Local<Object> name ## _handle = Local<Object>::New(name->handle_); \
    unsigned char* name ## _ptr = (unsigned char*)Buffer::Data(name ## _handle)

#define GET_ARG_AS(i, NAME, TYPE) \
    ARG_IS_BUFFER(i,#NAME); \
    TYPE NAME = (TYPE) Buffer::Data(args[i]->ToObject()); \
    unsigned long long NAME ## _size = Buffer::Length(args[i]->ToObject()); \
    if( NAME ## _size == 0 ) { \
        std::ostringstream oss; \
        oss << "argument " << #NAME << " length cannot be zero" ; \
        return ThrowException(Exception::Error(String::New(oss.str().c_str()))); \
    }

#define GET_ARG_AS_LEN(i, NAME, MAXLEN, TYPE) \
    GET_ARG_AS(i, NAME, TYPE); \
    if( NAME ## _size != MAXLEN ) { \
        std::ostringstream oss; \
        oss << "argument " << #NAME << " must be " << MAXLEN << " bytes long" ; \
        return ThrowException(Exception::Error(String::New(oss.str().c_str()))); \
    }

#define GET_ARG_AS_UCHAR(i, NAME) \
    GET_ARG_AS(i, NAME, unsigned char*)

#define GET_ARG_AS_UCHAR_LEN(i, NAME, MAXLEN) \
    GET_ARG_AS_LEN(i, NAME, MAXLEN, unsigned char*)

#define GET_ARG_AS_VOID(i, NAME) \
    GET_ARG_AS(i, NAME, void*)

#define GET_ARG_AS_VOID_LEN(i, NAME, MAXLEN) \
    GET_ARG_AS_LEN(i, NAME, MAXLEN, void*)


#define NUMBER_OF_MANDATORY_ARGS(n, message) \
    if (args.Length() < (n)) {                \
        return V8Exception(message);          \
    }
        
#define TO_REAL_BUFFER(slowBuffer, actualBuffer) \
    Handle<Value> constructorArgs ## slowBuffer[3] = \
        { slowBuffer->handle_, \
          v8::Integer::New(Buffer::Length(slowBuffer)), \
          v8::Integer::New(0) }; \
    Local<Object> actualBuffer = bufferConstructor->NewInstance(3, constructorArgs ## slowBuffer);
        
//Helper function
static Handle<Value> V8Exception(const char* msg) {
    return ThrowException(Exception::Error(String::New(msg)));
}

// Lib Sodium Version Functions
Handle<Value> bind_sodium_version_string(const Arguments& args) {
    HandleScope scope;
    return scope.Close(
        String::New(sodium_version_string())
    );
}

Handle<Value> bind_sodium_library_version_minor(const Arguments& args) {
    HandleScope scope;
    return scope.Close(
        Integer::New(sodium_library_version_minor())
    );
}

Handle<Value> bind_sodium_library_version_major(const Arguments& args) {
    HandleScope scope;
    return scope.Close(
        Integer::New(sodium_library_version_major())
    );
}

// Lib Sodium Utils
Handle<Value> bind_memzero(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument must be a buffer");
    GET_ARG_AS_VOID(0, buffer);
    sodium_memzero(buffer, buffer_size);
    return scope.Close(Null());
}

/** 
 * int sodium_memcmp(const void * const b1_, const void * const b2_, size_t size);
 */
Handle<Value> bind_memcmp(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"argument must be a buffer");

    GET_ARG_AS_VOID(0, buffer_1);
    GET_ARG_AS_VOID(1, buffer_2);

    size_t size;
    if (args[2]->IsUint32()) {
        size = args[2]->Int32Value();
    } else {
        return V8Exception("argument size must be a positive number");
    }

    size_t s = (buffer_1_size < buffer_2_size)? buffer_1_size : buffer_2_size;

    if( s < size ) {
        size = s;
    }
    
    return scope.Close(Integer::New(sodium_memcmp(buffer_1, buffer_2, size)));
}

/**
 * char *sodium_bin2hex(char * const hex, const size_t hexlen,
 *                    const unsigned char *bin, const size_t binlen);
 */
Handle<Value> bind_sodium_bin2hex(const Arguments& args) {
    HandleScope scope;
    return V8Exception("use node's native Buffer.toString()");
}

// Lib Sodium Random

// void randombytes_buf(void *const buf, const size_t size)
Handle<Value> bind_randombytes_buf(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument must be a buffer");

    GET_ARG_AS_VOID(0, buffer);
    randombytes_buf(buffer, buffer_size);
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

    NUMBER_OF_MANDATORY_ARGS(1,"argument size must be a positive number");
    
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

    NUMBER_OF_MANDATORY_ARGS(2,"arguments must be two buffers");
    
    GET_ARG_AS_UCHAR_LEN(0,string1, crypto_verify_16_BYTES);
    GET_ARG_AS_UCHAR_LEN(1,string2, crypto_verify_16_BYTES);
    
    return scope.Close(Integer::New(crypto_verify_16(string1, string2)));
}

// int crypto_verify_16(const unsigned char * string1, const unsigned char * string2)
Handle<Value> bind_crypto_verify_32(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments must be two buffers");
    
    GET_ARG_AS_UCHAR_LEN(0,string1, crypto_verify_32_BYTES);
    GET_ARG_AS_UCHAR_LEN(1,string2, crypto_verify_32_BYTES);

    return scope.Close(Integer::New(crypto_verify_32(string1, string2)));
}

/**
 * int crypto_shorthash(
 *    unsigned char *out,
 *    const unsigned char *in,
 *    unsigned long long inlen,
 *    const unsigned char *key)
 *
 * Parameters:
 *    [out] out    result of hash
 *    [in]  in     input buffer
 *    [in]  inlen  size of input buffer
 *    [in]  key    key buffer
 *
 * A lot of applications and programming language implementations have been
 * recently found to be vulnerable to denial-of-service attacks when a hash
 * function with weak security guarantees, like Murmurhash 3, was used to
 * construct a hash table.
 * In order to address this, Sodium provides the �shorthash� function,
 * currently implemented using SipHash-2-4. This very fast hash function
 * outputs short, but unpredictable (without knowing the secret key) values
 * suitable for picking a list in a hash table for a given key.
 */
Handle<Value> bind_crypto_shorthash(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument message must be a buffer");
    
    GET_ARG_AS_UCHAR(0,message);
    GET_ARG_AS_UCHAR_LEN(1, key, crypto_shorthash_KEYBYTES);
    
    NEW_BUFFER_AND_PTR(hash, crypto_shorthash_BYTES);
    
    if( crypto_shorthash(hash_ptr, message, message_size, key) == 0 ) {
        return scope.Close(hash->handle_);
    }
    return scope.Close(Null());
}

/**
 * int crypto_hash(
 *    unsigned char * hbuf,
 *    const unsigned char * msg,
 *    unsigned long long mlen)
 */
Handle<Value> bind_crypto_hash(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument message must be a buffer");
    
    GET_ARG_AS_UCHAR(0,msg);
    
    NEW_BUFFER_AND_PTR(hash, crypto_hash_BYTES);
    
    if( crypto_hash(hash_ptr, msg, msg_size) == 0 ) {
        return scope.Close(hash->handle_);
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

    NUMBER_OF_MANDATORY_ARGS(1,"argument message must be a buffer");    
    GET_ARG_AS_UCHAR(0, msg);
    NEW_BUFFER_AND_PTR(hash, 32);

    if( crypto_hash_sha256(hash_ptr, msg, msg_size) == 0 ) {
        return scope.Close(hash->handle_);
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

    NUMBER_OF_MANDATORY_ARGS(1,"argument message must be a buffer");
    
    GET_ARG_AS_UCHAR(0, msg);
    
    NEW_BUFFER_AND_PTR(hash, 64);

    if( crypto_hash_sha512(hash_ptr, msg, msg_size) == 0 ) {
        return scope.Close(hash->handle_);
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

    NUMBER_OF_MANDATORY_ARGS(2,"arguments message, and key must be buffers");
    
    GET_ARG_AS_UCHAR(0, msg);
    GET_ARG_AS_UCHAR_LEN(1, key, crypto_auth_KEYBYTES);
    
    NEW_BUFFER_AND_PTR(token, crypto_auth_BYTES);
    
    if( crypto_auth(token_ptr, msg, msg_size, key) == 0 ) {
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

    NUMBER_OF_MANDATORY_ARGS(3,"arguments token, message, and key must be buffers");
    
    GET_ARG_AS_UCHAR_LEN(0, token, crypto_auth_BYTES);
    GET_ARG_AS_UCHAR(1, message);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_auth_KEYBYTES);

    return scope.Close(Integer::New(crypto_auth_verify(token, message, message_size, key)));
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
    
    NUMBER_OF_MANDATORY_ARGS(2,"arguments message, and key must be buffers");
    
    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, key, crypto_onetimeauth_KEYBYTES);
    
    NEW_BUFFER_AND_PTR(token, crypto_onetimeauth_BYTES);

    if( crypto_onetimeauth(token_ptr, message, message_size, key) == 0 ) {
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

    NUMBER_OF_MANDATORY_ARGS(3,"arguments token, message, and key must be buffers");
    
    GET_ARG_AS_UCHAR_LEN(0, token, crypto_onetimeauth_BYTES);
    GET_ARG_AS_UCHAR(1, message);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_onetimeauth_KEYBYTES);

    return scope.Close(Integer::New(crypto_onetimeauth_verify(token, message, message_size, key)));
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
Handle<Value> bind_crypto_stream(const Arguments& args) {
    HandleScope scope;
    
    NUMBER_OF_MANDATORY_ARGS(3,"argument length must be a positive number, arguments nonce, and key must be buffers");
    
    if (!args[0]->IsUint32())
        return V8Exception("argument length must be positive number");
    
    unsigned long long slen = args[0]->ToUint32()->Value();
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_stream_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_stream_KEYBYTES);
    
    NEW_BUFFER_AND_PTR(stream, slen);

    if( crypto_stream(stream_ptr, slen, nonce, key) == 0) {
        return scope.Close(stream->handle_);
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
    
    NUMBER_OF_MANDATORY_ARGS(3,"arguments message, nonce, and key must be buffers");
    
    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_stream_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_stream_KEYBYTES);
    
    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if( crypto_stream_xor(ctxt_ptr, message, message_size, nonce, key) == 0) {
        return scope.Close(ctxt->handle_);
    }
    return scope.Close(Undefined());
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
Handle<Value> bind_crypto_secretbox(const Arguments& args) {
    HandleScope scope;
    
    NUMBER_OF_MANDATORY_ARGS(3,"arguments message, nonce, and key must be buffers");
    
    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_secretbox_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_secretbox_KEYBYTES);
    
    NEW_BUFFER_AND_PTR(pmb, message_size + crypto_secretbox_ZEROBYTES);

    // Fill the first crypto_secretbox_ZEROBYTES with 0
    unsigned int i;
    for(i=0; i < crypto_secretbox_ZEROBYTES; i++) {
        pmb_ptr[i] = 0U;
    }

    //Copy the message to the new buffer
    memcpy((void*) (pmb_ptr + crypto_secretbox_ZEROBYTES), (void *) message, message_size);
    message_size += crypto_secretbox_ZEROBYTES;
    
    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if( crypto_secretbox(ctxt_ptr, pmb_ptr, message_size, nonce, key) == 0) {
        return scope.Close(ctxt->handle_);
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
    
    NUMBER_OF_MANDATORY_ARGS(3,"arguments cipherText, nonce, and key must be buffers");
    
    GET_ARG_AS_UCHAR(0, cipher_text);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_secretbox_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, key, crypto_secretbox_KEYBYTES);
    
    NEW_BUFFER_AND_PTR(message, cipher_text_size);

    // API requires that the first crypto_secretbox_ZEROBYTES of msg be 0 so lets check
    if( cipher_text_size < crypto_secretbox_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "argument cipherText must have at least " << crypto_secretbox_BOXZEROBYTES << " bytes";
        return V8Exception(oss.str().c_str());
    }

    unsigned int i;
    for(i=0; i < crypto_secretbox_BOXZEROBYTES; i++) {
        if( cipher_text[i] ) break;
    }
    if( i < crypto_secretbox_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "the first " << crypto_secretbox_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        return V8Exception(oss.str().c_str());
    }

    if( crypto_secretbox_open(message_ptr, cipher_text, cipher_text_size, nonce, key) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text, cipher_text_size - crypto_secretbox_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (message_ptr + crypto_secretbox_ZEROBYTES), cipher_text_size - crypto_secretbox_ZEROBYTES);

        return scope.Close(plain_text->handle_);
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

    NUMBER_OF_MANDATORY_ARGS(2,"arguments message, and secretKey must be buffers");
    
    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, secretKey, crypto_sign_SECRETKEYBYTES);
    
    NEW_BUFFER_AND_PTR(sig, message_size + crypto_sign_BYTES);

    unsigned long long slen = 0;
    if( crypto_sign(sig_ptr, &slen, message, message_size, secretKey) == 0) {
        return scope.Close(sig->handle_);
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
    
    NEW_BUFFER_AND_PTR(vk, crypto_sign_PUBLICKEYBYTES);
    NEW_BUFFER_AND_PTR(sk, crypto_sign_SECRETKEYBYTES);

    if( crypto_sign_keypair(vk_ptr, sk_ptr) == 0) {
        Local<Object> result = Object::New();
        result->Set(String::NewSymbol("publicKey"), vk->handle_, DontDelete);
        result->Set(String::NewSymbol("secretKey"), sk->handle_, DontDelete);
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
    
    NUMBER_OF_MANDATORY_ARGS(2,"arguments signedMessage and verificationKey must be buffers");
    
    GET_ARG_AS_UCHAR(0, signedMessage);
    GET_ARG_AS_UCHAR_LEN(1, publicKey, crypto_sign_PUBLICKEYBYTES);

    unsigned long long mlen = 0;
    NEW_BUFFER_AND_PTR(msg, signedMessage_size);
    
    if( crypto_sign_open(msg_ptr, &mlen, signedMessage, signedMessage_size, publicKey) == 0) {
        NEW_BUFFER_AND_PTR(m, mlen);
        memcpy(m_ptr, msg_ptr, mlen);
        return scope.Close(m->handle_);
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
    
    NUMBER_OF_MANDATORY_ARGS(4,"arguments message, nonce, publicKey and secretKey must be buffers");
    
    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, publicKey, crypto_box_PUBLICKEYBYTES);
    GET_ARG_AS_UCHAR_LEN(3, secretKey, crypto_box_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(msg, message_size + crypto_box_ZEROBYTES);

    // Fill the first crypto_box_ZEROBYTES with 0
    unsigned int i;
    for(i=0; i < crypto_box_ZEROBYTES; i++) {
       msg_ptr[i] = 0U;
    }
    //Copy the message to the new buffer
    memcpy((void*) (msg_ptr + crypto_box_ZEROBYTES), (void *) message, message_size);
    message_size += crypto_box_ZEROBYTES;

    NEW_BUFFER_AND_PTR(ctxt, message_size);

    if( crypto_box(ctxt_ptr, msg_ptr, message_size, nonce, publicKey, secretKey) == 0) {
        return scope.Close(ctxt->handle_);
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
    
    NEW_BUFFER_AND_PTR(pk, crypto_box_PUBLICKEYBYTES);
    NEW_BUFFER_AND_PTR(sk, crypto_box_SECRETKEYBYTES);
    
    if( crypto_box_keypair(pk_ptr, sk_ptr) == 0) {
        Local<Object> result = Object::New();
        result->Set(String::NewSymbol("publicKey"), pk->handle_, DontDelete);
        result->Set(String::NewSymbol("secretKey"), sk->handle_, DontDelete);
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
    
    NUMBER_OF_MANDATORY_ARGS(4,"arguments cipherText, nonce, publicKey and secretKey must be buffers");
    
    GET_ARG_AS_UCHAR(0, cipherText);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, publicKey, crypto_box_PUBLICKEYBYTES);
    GET_ARG_AS_UCHAR_LEN(3, secretKey, crypto_box_SECRETKEYBYTES);    
    
    // API requires that the first crypto_box_BOXZEROBYTES of msg be 0 so lets check
    if( cipherText_size < crypto_box_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "argument cipherText must have a length of at least " << crypto_box_BOXZEROBYTES << " bytes";
        return V8Exception(oss.str().c_str());
    }
    
    unsigned int i;
    for(i=0; i < crypto_box_BOXZEROBYTES; i++) {
        if( cipherText[i] ) break;
    }
    if( i < crypto_box_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "the first " << crypto_box_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        return V8Exception(oss.str().c_str());
    }
    
    NEW_BUFFER_AND_PTR(msg, cipherText_size);
    
    if( crypto_box_open(msg_ptr, cipherText, cipherText_size, nonce, publicKey, secretKey) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text, cipherText_size - crypto_box_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (msg_ptr + crypto_box_ZEROBYTES), cipherText_size - crypto_box_ZEROBYTES);
        return scope.Close(plain_text->handle_);
    }
    return scope.Close(Undefined());
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
Handle<Value> bind_crypto_box_beforenm(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments publicKey, and secretKey must be buffers");
    
    GET_ARG_AS_UCHAR_LEN(0, publicKey, crypto_box_PUBLICKEYBYTES);
    GET_ARG_AS_UCHAR_LEN(1, secretKey, crypto_box_SECRETKEYBYTES);

    NEW_BUFFER_AND_PTR(k, crypto_box_BEFORENMBYTES);

    crypto_box_beforenm(k_ptr, publicKey, secretKey);
    return scope.Close(k->handle_);
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
Handle<Value> bind_crypto_box_afternm(const Arguments& args) {
    HandleScope scope;
    
    NUMBER_OF_MANDATORY_ARGS(3,"arguments message, nonce and k must be buffers");
    
    GET_ARG_AS_UCHAR(0, message);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, k, crypto_box_BEFORENMBYTES);

    // Pad the message with crypto_box_ZEROBYTES zeros
    NEW_BUFFER_AND_PTR(msg, message_size + crypto_box_ZEROBYTES);
    
    unsigned int i;
    for(i=0; i < crypto_box_ZEROBYTES; i++) {
       msg_ptr[i] = 0U;
    }
    //Copy the message to the new buffer
    memcpy((void*) (msg_ptr + crypto_box_ZEROBYTES), (void *) message, message_size);
    message_size += crypto_box_ZEROBYTES;

    NEW_BUFFER_AND_PTR(ctxt, message_size);
    
    if( crypto_box_afternm(ctxt_ptr, msg_ptr, message_size, nonce, k) == 0) {
        return scope.Close(ctxt->handle_);
    }
    return scope.Close(Undefined());
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
Handle<Value> bind_crypto_box_open_afternm(const Arguments& args) {
    HandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments cipherText, nonce, k");
    
    GET_ARG_AS_UCHAR(0, cipherText);
    GET_ARG_AS_UCHAR_LEN(1, nonce, crypto_box_NONCEBYTES);
    GET_ARG_AS_UCHAR_LEN(2, k, crypto_box_BEFORENMBYTES);

    // API requires that the first crypto_box_BOXZEROBYTES of msg be 0 so lets check
    if( cipherText_size < crypto_box_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "argument cipherText must have a length of at least " << crypto_box_BOXZEROBYTES << " bytes";
        return V8Exception(oss.str().c_str());
    }

    unsigned int i;
    for(i=0; i < crypto_box_BOXZEROBYTES; i++) {
        if( cipherText[i] ) break;
    }
    if( i < crypto_box_BOXZEROBYTES ) {
        std::ostringstream oss;
        oss << "the first " << crypto_box_BOXZEROBYTES << " bytes of argument cipherText must be 0";
        return V8Exception(oss.str().c_str());
    }

    NEW_BUFFER_AND_PTR(msg, cipherText_size);
    
    if( crypto_box_open_afternm(msg_ptr, cipherText, cipherText_size, nonce, k) == 0) {

        // Remove the padding at the beginning of the message
        NEW_BUFFER_AND_PTR(plain_text,cipherText_size - crypto_box_ZEROBYTES);
        memcpy(plain_text_ptr,(void*) (msg_ptr + crypto_box_ZEROBYTES), cipherText_size - crypto_box_ZEROBYTES);

        return scope.Close(plain_text->handle_);
    }
    return scope.Close(Undefined());
}

/**
 * int crypto_scalarmult_base(unsigned char *q, const unsigned char *n)
 */
Handle<Value> bind_crypto_scalarmult_base(const Arguments& args) {
    HandleScope scope;
    
    NUMBER_OF_MANDATORY_ARGS(1,"argument must be a buffer");
    
    GET_ARG_AS_UCHAR_LEN(0, n, crypto_scalarmult_SCALARBYTES);
    NEW_BUFFER_AND_PTR(q, crypto_scalarmult_BYTES);    

    if( crypto_scalarmult_base(q_ptr, n) == 0) {
        return scope.Close(q->handle_);
    }
    return scope.Close(Undefined());
}


/**
 * int crypto_scalarmult(unsigned char *q, const unsigned char *n,
 *                  const unsigned char *p)
 */
Handle<Value> bind_crypto_scalarmult(const Arguments& args) {
    HandleScope scope;
    
    NUMBER_OF_MANDATORY_ARGS(2,"arguments must be buffers");
    
    GET_ARG_AS_UCHAR_LEN(0, n, crypto_scalarmult_SCALARBYTES);
    GET_ARG_AS_UCHAR_LEN(1, p, crypto_scalarmult_BYTES);
    
    NEW_BUFFER_AND_PTR(q, crypto_scalarmult_BYTES);    

    if( crypto_scalarmult(q_ptr, n, p) == 0) {
        return scope.Close(q->handle_);
    }
    return scope.Close(Undefined());
}


#define NEW_INT_PROP(NAME) \
    target->Set(String::NewSymbol(#NAME), Integer::New(NAME), ReadOnly)

#define NEW_STRING_PROP(NAME) \
    target->Set(String::NewSymbol(#NAME), String::New(NAME), ReadOnly)

#define NEW_METHOD(NAME) \
    NODE_SET_METHOD(target, #NAME, bind_ ## NAME)

void RegisterModule(Handle<Object> target) {
    // init sodium library before we do anything
    sodium_init();

    // Register version functions
    NEW_METHOD(sodium_version_string);
    
    //NEW_METHOD(version);
    NEW_METHOD(sodium_library_version_minor);
    NEW_METHOD(sodium_library_version_major);

    // register utilities
    NEW_METHOD(memzero);
    NEW_METHOD(memcmp);

    // register random utilities
    NEW_METHOD(randombytes_buf);
    NODE_SET_METHOD(target, "randombytes", bind_randombytes_buf);
    NEW_METHOD(randombytes_close);
    NEW_METHOD(randombytes_stir);
    NEW_METHOD(randombytes_random);
    NEW_METHOD(randombytes_uniform);

    // String comparisons
    NEW_METHOD(crypto_verify_16);
    NEW_METHOD(crypto_verify_32);

    // Hash
    NEW_METHOD(crypto_hash);
    NEW_METHOD(crypto_hash_sha512);
    NEW_METHOD(crypto_hash_sha256);
    NEW_INT_PROP(crypto_hash_BYTES);
    NEW_INT_PROP(crypto_hash_sha256_BYTES);
    NEW_INT_PROP(crypto_hash_sha512_BYTES);
    NEW_INT_PROP(crypto_hash_BLOCKBYTES);
    NEW_STRING_PROP(crypto_hash_PRIMITIVE);

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

    /*
     * Not implemented in the default crypto_stream, only in the AES variations which are not
     * ported yet
    NEW_METHOD(crypto_stream_beforenm);
    NEW_METHOD(crypto_stream_afternm);
    NEW_METHOD(crypto_stream_xor_afternm);
    */

    // Secret Box
    NEW_METHOD(crypto_secretbox);
    NEW_METHOD(crypto_secretbox_open);
    NEW_INT_PROP(crypto_secretbox_BOXZEROBYTES);
    NEW_INT_PROP(crypto_secretbox_KEYBYTES);
    NEW_INT_PROP(crypto_secretbox_NONCEBYTES);
    NEW_INT_PROP(crypto_secretbox_ZEROBYTES);
    NEW_STRING_PROP(crypto_secretbox_PRIMITIVE);

    // Sign
    NEW_METHOD(crypto_sign);
    NEW_METHOD(crypto_sign_keypair);
    NEW_METHOD(crypto_sign_open);
    NEW_INT_PROP(crypto_sign_BYTES);
    NEW_INT_PROP(crypto_sign_PUBLICKEYBYTES);
    NEW_INT_PROP(crypto_sign_SECRETKEYBYTES);
    NEW_STRING_PROP(crypto_sign_PRIMITIVE);
    
    // Box
    NEW_METHOD(crypto_box);
    NEW_METHOD(crypto_box_keypair);
    NEW_METHOD(crypto_box_open);
    NEW_METHOD(crypto_box_beforenm);
    NEW_METHOD(crypto_box_afternm);
    NEW_METHOD(crypto_box_open_afternm);
    NEW_INT_PROP(crypto_box_NONCEBYTES);
    NEW_INT_PROP(crypto_box_BEFORENMBYTES);
    NEW_INT_PROP(crypto_box_BOXZEROBYTES);
    NEW_INT_PROP(crypto_box_PUBLICKEYBYTES);
    NEW_INT_PROP(crypto_box_SECRETKEYBYTES);
    NEW_INT_PROP(crypto_box_ZEROBYTES);
    NEW_STRING_PROP(crypto_box_PRIMITIVE);

    NEW_METHOD(crypto_shorthash);
    NEW_INT_PROP(crypto_shorthash_BYTES);
    NEW_INT_PROP(crypto_shorthash_KEYBYTES);
    NEW_STRING_PROP(crypto_shorthash_PRIMITIVE);
    
    // Scalar Mult
    NEW_METHOD(crypto_scalarmult);
    NEW_METHOD(crypto_scalarmult_base);
    NEW_INT_PROP(crypto_scalarmult_SCALARBYTES);
    NEW_INT_PROP(crypto_scalarmult_BYTES);
    NEW_STRING_PROP(crypto_scalarmult_PRIMITIVE);
    
}

NODE_MODULE(sodium, RegisterModule);