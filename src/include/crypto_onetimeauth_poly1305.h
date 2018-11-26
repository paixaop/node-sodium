/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __CRYPTO_ONETIMEAUTH_POLY1305_H__
#define __CRYPTO_ONETIMEAUTH_POLY1305_H__

#include "node_sodium.h"

NAPI_METHOD(crypto_onetimeauth_poly1305);
NAPI_METHOD(crypto_onetimeauth_poly1305_verify);
NAPI_METHOD(crypto_onetimeauth_poly1305_init);
NAPI_METHOD(crypto_onetimeauth_poly1305_update);
NAPI_METHOD(crypto_onetimeauth_poly1305_final);
NAPI_METHOD(crypto_onetimeauth_poly1305_keygen);

#endif