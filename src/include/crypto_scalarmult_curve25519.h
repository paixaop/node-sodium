/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __CRYPTO_SCALARMULT_CURVE25519_H__
#define __CRYPTO_SCALARMULT_CURVE25519_H__

Napi::Value bind_crypto_scalarmult_curve25519(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_scalarmult_curve25519_base(const Napi::CallbackInfo& info);

#endif