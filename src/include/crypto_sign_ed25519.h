/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __CRYPTO_SIGN_ED25519_H__
#define __CRYPTO_SIGN_ED25519_H__

Napi::Value bind_crypto_sign_ed25519(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_sign_ed25519_open(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_sign_ed25519_detached(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_sign_ed25519_verify_detached(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_sign_ed25519_keypair(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_sign_ed25519_seed_keypair(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_sign_ed25519_pk_to_curve25519(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_sign_ed25519_sk_to_curve25519(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_sign_ed25519_sk_to_seed(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_sign_ed25519_sk_to_pk(const Napi::CallbackInfo& info);
    
#endif