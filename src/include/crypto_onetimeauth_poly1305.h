/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __CRYPTO_ONETIMEAUTH_POLY1305_H__
#define __CRYPTO_ONETIMEAUTH_POLY1305_H__

Napi::Value bind_crypto_onetimeauth_poly1305(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_onetimeauth_poly1305_verify(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_onetimeauth_poly1305_init(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_onetimeauth_poly1305_update(const Napi::CallbackInfo& info);
Napi::Value bind_crypto_onetimeauth_poly1305_final(const Napi::CallbackInfo& info);

#endif