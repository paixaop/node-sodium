#ifndef __NODE_SODIUM_REGISTER_H__
#define __NODE_SODIUM_REGISTER_H__

#include <napi.h>
#include <uv.h>

void register_helpers(Napi::Env env, Napi::Object exports);
void register_randombytes(Napi::Env env, Napi::Object exports);
void register_crypto_pwhash_algos(Napi::Env env, Napi::Object exports);
void register_crypto_pwhash(Napi::Env env, Napi::Object exports);
void register_crypto_hash(Napi::Env env, Napi::Object exports);
void register_crypto_hash_sha256(Napi::Env env, Napi::Object exports);
void register_crypto_hash_sha512(Napi::Env env, Napi::Object exports);
void register_crypto_shorthash(Napi::Env env, Napi::Object exports);
void register_crypto_shorthash_siphash24(Napi::Env env, Napi::Object exports);
void register_crypto_generichash(Napi::Env env, Napi::Object exports);
void register_crypto_generichash_blake2b(Napi::Env env, Napi::Object exports);
void register_crypto_auth(Napi::Env env, Napi::Object exports);
void register_crypto_onetimeauth(Napi::Env env, Napi::Object exports);
void register_crypto_onetimeauth_poly1305(Napi::Env env, Napi::Object exports);
void register_crypto_stream(Napi::Env env, Napi::Object exports);
void register_crypto_streams(Napi::Env env, Napi::Object exports);
void register_crypto_secretbox(Napi::Env env, Napi::Object exports);
void register_crypto_secretbox_xsalsa20poly1305(Napi::Env env, Napi::Object exports);
void register_crypto_sign(Napi::Env env, Napi::Object exports);
void register_crypto_sign_ed25519(Napi::Env env, Napi::Object exports);
void register_crypto_box(Napi::Env env, Napi::Object exports);
void register_crypto_scalarmult(Napi::Env env, Napi::Object exports);
void register_crypto_scalarmult_curve25519(Napi::Env env, Napi::Object exports);
void register_crypto_core(Napi::Env env, Napi::Object exports);
void register_crypto_auth_algos(Napi::Env env, Napi::Object exports);
void register_crypto_aead(Napi::Env env, Napi::Object exports);
void register_runtime(Napi::Env env, Napi::Object exports);
void register_crypto_box_curve25519xsalsa20poly1305(Napi::Env env, Napi::Object exports);

#endif
