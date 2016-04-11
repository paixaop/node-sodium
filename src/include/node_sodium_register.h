#ifndef __NODE_SODIUM_REGISTER_H__
#define __NODE_SODIUM_REGISTER_H__

#include <node.h>

void register_helpers(Handle<Object> target);
void register_randombytes(Handle<Object> target);
void register_crypto_pwhash(Handle<Object> target);
void register_crypto_hash(Handle<Object> target);
void register_crypto_hash_sha256(Handle<Object> target);
void register_crypto_hash_sha512(Handle<Object> target);


#endif
