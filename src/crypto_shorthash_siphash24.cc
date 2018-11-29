/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * int crypto_shorthash_siphash24(
 *    unsigned char *out,
 *    const unsigned char *in,
 *    unsigned long long inlen,
 *    const unsigned char *key)
 *
 * Parameters:
 *    [out] out    result of hash
 *    [in]  in     input buffer
 *    [in]  inlen  size of input buffer
 *    [in]  key    key buffer
 *
 * A lot of applications and programming language implementations have been
 * recently found to be vulnerable to denial-of-service attacks when a hash
 * function with weak security guarantees, like Murmurhash 3, was used to
 * construct a hash table.
 * In order to address this, Sodium provides the shorthash function,
 * currently implemented using SipHash-2-4. This very fast hash function
 * outputs short, but unpredictable (without knowing the secret key) values
 * suitable for picking a list in a hash table for a given key.
 */
NAPI_METHOD(crypto_shorthash_siphash24) {
    Napi::Env env = info.Env();

    ARGS(1, "argument message must be a buffer");
    ARG_TO_UCHAR_BUFFER(message);
    ARG_TO_UCHAR_BUFFER_LEN(key, crypto_shorthash_siphash24_KEYBYTES);

    NEW_BUFFER_AND_PTR(hash, crypto_shorthash_siphash24_BYTES);

    if( crypto_shorthash_siphash24(hash_ptr, message, message_size, key) == 0 ) {
        return hash;
    }
    
    return NAPI_NULL;
}

/**
 * Register function calls in node binding
 */
void register_crypto_shorthash_siphash24(Napi::Env env, Napi::Object exports) {

    // Short Hash
    EXPORT(crypto_shorthash_siphash24);
    EXPORT_INT(crypto_shorthash_siphash24_BYTES);
    EXPORT_INT(crypto_shorthash_siphash24_KEYBYTES);
}