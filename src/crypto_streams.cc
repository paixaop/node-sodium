/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"
#include "crypto_streams.h"

CRYPTO_STREAM_DEF(aes128ctr)
CRYPTO_STREAM_DEF(salsa20)    
CRYPTO_STREAM_DEF(xsalsa20)
CRYPTO_STREAM_DEF(salsa208)
CRYPTO_STREAM_DEF(salsa2012)
CRYPTO_STREAM_DEF(chacha20)

// chacha_ietf uses the same key length as crypto_stream_chacha20_KEYBYTES
// Libsodium does not define it, lets define it here so we don't get compilation errors
// when expanding the macros
#define crypto_stream_chacha20_ietf_KEYBYTES   crypto_stream_chacha20_KEYBYTES
#define crypto_stream_chacha20_ietf_NONCEBYTES crypto_stream_chacha20_IETF_NONCEBYTES
CRYPTO_STREAM_DEF(chacha20_ietf)

/**
 * Register function calls in node binding
 */
void register_crypto_streams(Handle<Object> target) {
    
    METHODS(xsalsa20);
    PROPS(xsalsa20);
    
    METHODS(salsa20);
    PROPS(salsa20);
    
    METHODS(salsa208);
    PROPS(salsa208);
    
    METHODS(salsa2012);
    PROPS(salsa2012);
    
    METHODS(chacha20);
    PROPS(chacha20);
    
    METHODS(chacha20_ietf);
    PROPS(chacha20_ietf);
    
    METHODS(aes128ctr);
    PROPS(aes128ctr);
}