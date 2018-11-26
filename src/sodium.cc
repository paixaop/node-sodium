/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"
#include "node_sodium_register.h"

Napi::Object RegisterModule(Napi::Env env, Napi::Object exports) {
//void RegisterModule(Handle<Object> target) {
    // init sodium library before we do anything
    if( sodium_init() == -1 ) {
        Napi::Error::New(env, "libsodium cannot be initialized!").ThrowAsJavaScriptException();
        return Napi::Object::New(env);
    }

    randombytes_stir();

    register_helpers(env, exports);
    register_runtime(env, exports);
    register_randombytes(env, exports);
    register_crypto_pwhash_algos(env, exports);
    register_crypto_pwhash(env, exports);
    register_crypto_hash(env, exports);
    register_crypto_hash_sha256(env, exports);
    register_crypto_hash_sha512(env, exports);
    register_crypto_shorthash(env, exports);
    register_crypto_shorthash_siphash24(env, exports);
    register_crypto_generichash(env, exports);
    register_crypto_generichash_blake2b(env, exports);
    register_crypto_auth_algos(env, exports);
    register_crypto_auth(env, exports);
    register_crypto_onetimeauth(env, exports);
    register_crypto_onetimeauth_poly1305(env, exports);
    register_crypto_stream(env, exports);
    register_crypto_streams(env, exports);
    register_crypto_secretbox(env, exports);
    register_crypto_secretbox_xsalsa20poly1305(env, exports);
    register_crypto_sign(env, exports);
    register_crypto_sign_ed25519(env, exports);
    register_crypto_box(env, exports);
    register_crypto_box_curve25519xsalsa20poly1305(env, exports);
    register_crypto_scalarmult(env, exports);
    register_crypto_scalarmult_curve25519(env, exports);
    register_crypto_core(env, exports);
    register_crypto_aead(env, exports);
    
    return exports;
}

NODE_API_MODULE(sodium, RegisterModule);
