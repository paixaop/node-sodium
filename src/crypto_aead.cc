/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"
#include "crypto_aead.h"

NAN_METHOD(bind_crypto_aead_aes256gcm_is_available) {
    Nan::EscapableHandleScope scope;

    if( crypto_aead_aes256gcm_is_available() == 1 ) {
        return info.GetReturnValue().Set(Nan::True());
    }
    
    return info.GetReturnValue().Set(Nan::False());
}

CRYPTO_AEAD_DEF(aes256gcm)
CRYPTO_AEAD_DETACHED_DEF(aes256gcm)

CRYPTO_AEAD_DEF(chacha20poly1305)
CRYPTO_AEAD_DETACHED_DEF(chacha20poly1305)

CRYPTO_AEAD_DEF(chacha20poly1305_ietf)
CRYPTO_AEAD_DETACHED_DEF(chacha20poly1305_ietf)

/**
 * Register function calls in node binding
 */
void register_crypto_aead(Handle<Object> target) {
    NEW_METHOD(crypto_aead_aes256gcm_is_available);
    METHOD_AND_PROPS(aes256gcm);
    METHOD_AND_PROPS(chacha20poly1305);
    METHOD_AND_PROPS(chacha20poly1305_ietf);
}