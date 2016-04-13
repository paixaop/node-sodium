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
 * int crypto_scalarmult_base(unsigned char *q, const unsigned char *n)
 */
NAN_METHOD(bind_crypto_scalarmult_base) {
    Nan::EscapableHandleScope scope;

    ARGS(1,"argument must be a buffer");
    ARG_TO_UCHAR_BUFFER_LEN(n, crypto_scalarmult_SCALARBYTES);
    
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

    ARGS(2,"arguments must be buffers");
    ARG_TO_UCHAR_BUFFER_LEN(n, crypto_scalarmult_SCALARBYTES);
    ARG_TO_UCHAR_BUFFER_LEN(p, crypto_scalarmult_BYTES);

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
    register_crypto_generichash_blake2b(target);
    register_crypto_auth(target);
    register_crypto_onetimeauth(target);
    register_crypto_onetimeauth_poly1305(target);
    register_crypto_stream(target);
    register_crypto_streams(target);
    register_crypto_secretbox(target);
    register_crypto_secretbox_xsalsa20poly1305(target);
    register_crypto_sign(target);
    register_crypto_box( target);

    // Scalar Mult
    NEW_METHOD(crypto_scalarmult);
    NEW_METHOD(crypto_scalarmult_base);
    NEW_INT_PROP(crypto_scalarmult_SCALARBYTES);
    NEW_INT_PROP(crypto_scalarmult_BYTES);
    NEW_STRING_PROP(crypto_scalarmult_PRIMITIVE);

}

NODE_MODULE(sodium, RegisterModule);
