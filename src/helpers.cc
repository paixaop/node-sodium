/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

// Lib Sodium Version Functions
Napi::Value bind_sodium_version_string(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    return Napi::String::New(env, sodium_version_string());
}

Napi::Value bind_sodium_library_version_minor(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    return 
        Napi::Value::From(env, sodium_library_version_minor());
}

Napi::Value bind_sodium_library_version_major(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    return 
        Napi::Value::From(env, sodium_library_version_major());
}

// Lib Sodium Utils
Napi::Value bind_memzero(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(1,"argument must be a buffer");
    ARG_TO_UCHAR_BUFFER(buffer);  // VOID
    
    sodium_memzero(buffer, buffer_size);
    return env.Null();
}

/**
 * int sodium_memcmp(const void * const b1_, const void * const b2_, size_t size);
 */
Napi::Value bind_memcmp(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(3,"arguments must be: buffer, buffer, positive number");

    ARG_TO_UCHAR_BUFFER(buffer_1);  // VOID
    ARG_TO_UCHAR_BUFFER(buffer_2);  // VOID
    ARG_TO_NUMBER(size);
    
    size_t s = (buffer_1_size < buffer_2_size)? buffer_1_size : buffer_2_size;

    if( s < size ) {
        size = s;
    }

    return 
        Napi::Number::New(env, sodium_memcmp(buffer_1, buffer_2, size))
    ;
}

/**
 * char *sodium_bin2hex(char * const hex, const size_t hexlen,
 *                    const unsigned char *bin, const size_t binlen);
 */
Napi::Value bind_bin2hex(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    Napi::Error::New(env, "use node's native Buffer.toString()").ThrowAsJavaScriptException();
    return env.Null();
}

Napi::Value bind_hex2bin(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    Napi::Error::New(env, "use node's native Buffer.toString()").ThrowAsJavaScriptException();
    return env.Null();
}

Napi::Value bind_crypto_verify_16(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(2,"arguments must be two buffers");
    ARG_TO_UCHAR_BUFFER_LEN(string1, crypto_verify_16_BYTES);
    ARG_TO_UCHAR_BUFFER_LEN(string2, crypto_verify_16_BYTES);

    return 
        Napi::Number::New(env, crypto_verify_16(string1, string2));
}

// int crypto_verify_16(const unsigned char * string1, const unsigned char * string2)
Napi::Value bind_crypto_verify_32(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(2,"arguments must be two buffers");
    ARG_TO_UCHAR_BUFFER_LEN(string1, crypto_verify_32_BYTES);
    ARG_TO_UCHAR_BUFFER_LEN(string2, crypto_verify_32_BYTES);

    return 
        Napi::Number::New(env, crypto_verify_32(string1, string2));
}

// int crypto_verify_64(const unsigned char * string1, const unsigned char * string2)
Napi::Value bind_crypto_verify_64(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(2,"arguments must be two buffers");
    ARG_TO_UCHAR_BUFFER_LEN(string1, crypto_verify_64_BYTES);
    ARG_TO_UCHAR_BUFFER_LEN(string2, crypto_verify_64_BYTES);

    return 
        Napi::Number::New(env, crypto_verify_64(string1, string2));
}

/**
 * void sodium_increment(unsigned char *n, const size_t nlen);
 *
 */
Napi::Value bind_increment(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(1,"argument must be a buffer");
    ARG_TO_UCHAR_BUFFER(buffer);
    
    sodium_increment(buffer, buffer_size);

    return env.Null();
}

/**
 * int sodium_compare(const unsigned char *b1_, const unsigned char *b2, size_t len);
 */
Napi::Value bind_compare(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(2,"arguments must be two buffers");
    ARG_TO_UCHAR_BUFFER(buffer_1);
    ARG_TO_UCHAR_BUFFER(buffer_2);

    if( buffer_1_size != buffer_2_size ) {
        Napi::Error::New(env, "buffers need to be the same size").ThrowAsJavaScriptException();
        return env.Null();
    }

    return 
        Napi::Number::New(env, sodium_compare(buffer_1, buffer_2, buffer_1_size));
}

/**
 * void sodium_add(unsigned char *a, const unsigned char *b, const size_t len);
 */
Napi::Value bind_add(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(2,"arguments must be two buffers");
    ARG_TO_UCHAR_BUFFER(buffer_1);
    ARG_TO_UCHAR_BUFFER(buffer_2);

    if( buffer_1_size != buffer_2_size ) {
        Napi::Error::New(env, "buffers need to be the same size").ThrowAsJavaScriptException();
        return env.Null();
    }
    sodium_add(buffer_1, buffer_2, buffer_1_size);
    return env.Null();
}

/**
 * `int sodium_is_zero(const unsigned char *n, const size_t nlen);
 */
Napi::Value bind_is_zero(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(1,"argument must be a buffer");
    ARG_TO_UCHAR_BUFFER(buffer_1);

    return 
        Napi::Number::New(env, sodium_is_zero(buffer_1, buffer_1_size));
}

/**
 * Register function calls in node binding
 */
void register_helpers(Napi::Env env, Napi::Object exports) {
    // Register version functions
    EXPORT(sodium_version_string);
    EXPORT(sodium_library_version_minor);
    EXPORT(sodium_library_version_major);
    
    // Constant-time test for equality
    EXPORT(memcmp);
    EXPORT(memzero);

    // String comparisons
    EXPORT(crypto_verify_16);
    EXPORT(crypto_verify_32);
    EXPORT(crypto_verify_64);
    NEW_INT_PROP(crypto_verify_16_BYTES);
    NEW_INT_PROP(crypto_verify_32_BYTES);
    NEW_INT_PROP(crypto_verify_64_BYTES);
    
    // Hexadecimal encoding/decoding
    EXPORT(bin2hex);
    EXPORT(hex2bin);
    
    // Large Numbers
    EXPORT(increment);
    EXPORT(add);
    EXPORT(compare);
    EXPORT(is_zero);
}