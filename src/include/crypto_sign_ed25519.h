/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __CRYPTO_SIGN_ED25519_H__
#define __CRYPTO_SIGN_ED25519_H__

#include "node_sodium.h"

NAPI_METHOD(crypto_sign_ed25519);
NAPI_METHOD(crypto_sign_ed25519_open);
NAPI_METHOD(crypto_sign_ed25519_detached);
NAPI_METHOD(crypto_sign_ed25519_verify_detached);
NAPI_METHOD(crypto_sign_ed25519_keypair);
NAPI_METHOD(crypto_sign_ed25519_seed_keypair);
NAPI_METHOD(crypto_sign_ed25519_pk_to_curve25519);
NAPI_METHOD(crypto_sign_ed25519_sk_to_curve25519);
NAPI_METHOD(crypto_sign_ed25519_sk_to_seed);
NAPI_METHOD(crypto_sign_ed25519_sk_to_pk);
    
#endif