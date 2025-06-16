/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"
#include "crypto_pwhash_algos.h"


CRYPTO_PWHASH_DEF_EXT(argon2i)
CRYPTO_PWHASH_DEF_STR(argon2i)
NAPI_METHOD_FROM_INT(crypto_pwhash_argon2i_opslimit_moderate)
NAPI_METHOD_FROM_INT(crypto_pwhash_argon2i_memlimit_moderate)
NAPI_METHOD_FROM_INT(crypto_pwhash_argon2i_alg_argon2i13);


CRYPTO_PWHASH_DEF_EXT(argon2id)
CRYPTO_PWHASH_DEF_STR(argon2id)
NAPI_METHOD_FROM_INT(crypto_pwhash_argon2id_opslimit_moderate)
NAPI_METHOD_FROM_INT(crypto_pwhash_argon2id_memlimit_moderate)
NAPI_METHOD_FROM_INT(crypto_pwhash_argon2id_alg_argon2id13);

CRYPTO_PWHASH_DEF(scryptsalsa208sha256)
CRYPTO_PWHASH_DEF_STR(scryptsalsa208sha256)
CRYPTO_PWHASH_DEF_LL(scryptsalsa208sha256)

/**
 * Register function calls in node binding
 */
void register_crypto_pwhash_algos(Napi::Env env, Napi::Object exports) {
    METHOD_AND_PROPS(argon2i);
    EXPORT(crypto_pwhash_argon2i_opslimit_moderate);
    EXPORT(crypto_pwhash_argon2i_memlimit_moderate);
    EXPORT_INT(crypto_pwhash_argon2i_OPSLIMIT_MODERATE);
    EXPORT_INT(crypto_pwhash_argon2i_MEMLIMIT_MODERATE);
    EXPORT(crypto_pwhash_argon2i_alg_argon2i13);
    EXPORT_INT(crypto_pwhash_argon2i_ALG_ARGON2I13);

    METHOD_AND_PROPS(argon2id);
    EXPORT(crypto_pwhash_argon2id_opslimit_moderate);
    EXPORT(crypto_pwhash_argon2id_memlimit_moderate);
    EXPORT_INT(crypto_pwhash_argon2id_OPSLIMIT_MODERATE);
    EXPORT_INT(crypto_pwhash_argon2id_MEMLIMIT_MODERATE);

    METHOD_AND_PROPS(scryptsalsa208sha256);
    EXPORT(crypto_pwhash_scryptsalsa208sha256_ll);

    EXPORT(crypto_pwhash_argon2id_opslimit_moderate);
    EXPORT(crypto_pwhash_argon2id_memlimit_moderate);
    EXPORT_INT(crypto_pwhash_argon2id_MEMLIMIT_MODERATE);
    EXPORT(crypto_pwhash_argon2id_alg_argon2id13);
}