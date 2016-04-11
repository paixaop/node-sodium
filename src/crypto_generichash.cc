/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

/**
 * int crypto_generichash(unsigned char *out,
 *                        size_t outlen,
 *                        const unsigned char *in,
 *                        unsigned long long inlen,
 *                        const unsigned char *key,
 *                        size_t keylen);
 *  buffer out,
 *  number out_size,
 *  buffer in,
 *  buffer key
 */
NAN_METHOD(bind_crypto_generichash) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(3,"arguments must be: hash size, message, key");
    
    GET_ARG_POSITIVE_NUMBER(0, out_size);
    
    if( out_size > crypto_generichash_BYTES_MAX ) {
        std::ostringstream oss;
        oss << "generichash output size cannot be bigger than " << crypto_generichash_BYTES_MAX << " bytes"; 
        return Nan::ThrowError(oss.str().c_str());
    }
    
    if( out_size < crypto_generichash_BYTES_MIN ) {
        std::ostringstream oss;
        oss << "generichash output size cannot be smaller than " << crypto_generichash_BYTES_MIN << " bytes"; 
        return Nan::ThrowError(oss.str().c_str());
    }
    
    GET_ARG_AS_UCHAR(1, in);
    GET_ARG_AS_UCHAR(2, key);
    
    if( key_size > crypto_generichash_KEYBYTES_MAX ) {
        std::ostringstream oss;
        oss << "generichash key size cannot be bigger than " << crypto_generichash_BYTES_MAX << " bytes"; 
        return Nan::ThrowError(oss.str().c_str());
    }
    
    if( key_size != 0 && key_size < crypto_generichash_KEYBYTES_MIN ) {
        std::ostringstream oss;
        oss << "generichash key size cannot be smaller than " << crypto_generichash_BYTES_MIN << " bytes"; 
        return Nan::ThrowError(oss.str().c_str());
    }

    NEW_BUFFER_AND_PTR(hash, out_size);
    memset(hash_ptr, 0, out_size);

    if (crypto_generichash(hash_ptr, out_size, in, in_size, key, key_size) == 0) {
        return info.GetReturnValue().Set(hash);
    } else {
        return info.GetReturnValue().Set(Nan::Null());
    } 
}

/*
int crypto_generichash_init(crypto_generichash_state *state,
                            const unsigned char *key,
                            const size_t keylen, const size_t outlen);
  Buffer state
  Buffer key
  Number out_size
  state = sodium_malloc((crypto_generichash_statebytes() + (size_t) 63U)
 *                       & ~(size_t) 63U);
*/
NAN_METHOD(bind_crypto_generichash_init) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments must be: key, out_size");
    
    NEW_BUFFER_AND_PTR(state, (crypto_generichash_statebytes() + (size_t) 63U)
                        & ~(size_t) 63U);
    
    GET_ARG_AS_UCHAR(0, key);
    
    if( key_size > crypto_generichash_KEYBYTES_MAX ) {
        std::ostringstream oss;
        oss << "generichash key size cannot be bigger than " << crypto_generichash_BYTES_MAX << " bytes"; 
        return Nan::ThrowError(oss.str().c_str());
    }
    
    if( key_size != 0 && key_size < crypto_generichash_KEYBYTES_MIN ) {
        std::ostringstream oss;
        oss << "generichash key size cannot be smaller than " << crypto_generichash_BYTES_MIN << " bytes"; 
        return Nan::ThrowError(oss.str().c_str());
    }
    
    GET_ARG_POSITIVE_NUMBER(1, out_size);
    
    if( out_size > crypto_generichash_BYTES_MAX ) {
        std::ostringstream oss;
        oss << "generichash output size cannot be bigger than " << crypto_generichash_BYTES_MAX << " bytes"; 
        return Nan::ThrowError(oss.str().c_str());
    }
    
    if( out_size < crypto_generichash_BYTES_MIN ) {
        std::ostringstream oss;
        oss << "generichash output size cannot be smaller than " << crypto_generichash_BYTES_MIN << " bytes"; 
        return Nan::ThrowError(oss.str().c_str());
    }
    
    if (crypto_generichash_init((crypto_generichash_state *)state_ptr, key, key_size, out_size) == 0) {
        return info.GetReturnValue().Set(state);
    } else {
        return info.GetReturnValue().Set(Nan::Null());
    } 
}


/*
int crypto_generichash_update(crypto_generichash_state *state,
                              const unsigned char *in,
                              unsigned long long inlen);
                              
    buffer state
    buffer message
*/
NAN_METHOD(bind_crypto_generichash_update) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments must be: state, message");
    
    GET_ARG_AS_VOID(0, state);
    GET_ARG_AS_UCHAR(1, message);
    
    crypto_generichash_update((crypto_generichash_state *)state, message, message_size);
    return info.GetReturnValue().Set(Nan::Null()); 
}

/*
int crypto_generichash_final(crypto_generichash_state *state,
                             unsigned char *out, const size_t outlen);
*/
NAN_METHOD(bind_crypto_generichash_final) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(2,"arguments must be: state, out_size");
    
    GET_ARG_AS_VOID(0, state);
    GET_ARG_POSITIVE_NUMBER(1, out_size);
    
    if( out_size > crypto_generichash_BYTES_MAX ) {
        std::ostringstream oss;
        oss << "generichash output size cannot be bigger than " << crypto_generichash_BYTES_MAX << " bytes"; 
        return Nan::ThrowError(oss.str().c_str());
    }
    
    if( out_size < crypto_generichash_BYTES_MIN ) {
        std::ostringstream oss;
        oss << "generichash output size cannot be smaller than " << crypto_generichash_BYTES_MIN << " bytes"; 
        return Nan::ThrowError(oss.str().c_str());
    }
    
    NEW_BUFFER_AND_PTR(hash, out_size);
    
    if (crypto_generichash_final((crypto_generichash_state *)state, hash_ptr, out_size) == 0) {
        return info.GetReturnValue().Set(hash);
    } else {
        return info.GetReturnValue().Set(Nan::Null());
    } 
}

/**
 * Register function calls in node binding
 */
void register_crypto_generichash(Handle<Object> target) {
     // Generic Hash
    NEW_METHOD(crypto_generichash);
    NEW_METHOD(crypto_generichash_init);
    NEW_METHOD(crypto_generichash_update);
    NEW_METHOD(crypto_generichash_final);
    NEW_STRING_PROP(crypto_generichash_PRIMITIVE);
    NEW_INT_PROP(crypto_generichash_BYTES);
    NEW_INT_PROP(crypto_generichash_BYTES_MIN);
    NEW_INT_PROP(crypto_generichash_BYTES_MAX);
    NEW_INT_PROP(crypto_generichash_KEYBYTES);
    NEW_INT_PROP(crypto_generichash_KEYBYTES_MIN);
    NEW_INT_PROP(crypto_generichash_KEYBYTES_MAX);
}