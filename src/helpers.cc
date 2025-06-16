/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

// Lib Sodium Version Functions
NAPI_METHOD(sodium_version_string) {
    Napi::Env env = info.Env();

    return Napi::String::New(env, sodium_version_string());
}

NAPI_METHOD(sodium_library_version_minor) {
    Napi::Env env = info.Env();

    return 
        Napi::Value::From(env, sodium_library_version_minor());
}

NAPI_METHOD(sodium_library_version_major) {
    Napi::Env env = info.Env();

    return 
        Napi::Value::From(env, sodium_library_version_major());
}

// Lib Sodium Utils
NAPI_METHOD(memzero) {
    Napi::Env env = info.Env();

    ARGS(1, "argument must be a buffer");
    ARG_TO_UCHAR_BUFFER(buffer);  // VOID
    
    sodium_memzero(buffer, buffer_size);
    return NAPI_NULL;
}

/**
 * int sodium_memcmp(const void * const b1_, const void * const b2_, size_t size);
 */
NAPI_METHOD(memcmp) {
    Napi::Env env = info.Env();

    ARGS(3, "arguments must be: buffer, buffer, positive number");

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
NAPI_METHOD(bin2hex) {
    Napi::Env env = info.Env();

    Napi::Error::New(env, "use node's native Buffer.toString()").ThrowAsJavaScriptException();
    return NAPI_NULL;
}

/* int sodium_hex2bin(unsigned char * const bin, const size_t bin_maxlen,
 *                  const char * const hex, const size_t hex_len,
 *                  const char * const ignore, size_t * const bin_len,
 *                  const char ** const hex_end);
 */
NAPI_METHOD(hex2bin) {
    Napi::Env env = info.Env();
   /* ARGS();
    ARG_TO_NUMBER(bin_maxlen);
    ARG_TO_STRING(hex);
    ARG_TO_STRING(ignore);
    ARG_TO_UCA*/
    Napi::Error::New(env, "use node's native Buffer.toString()").ThrowAsJavaScriptException();
    return NAPI_NULL;
}

NAPI_METHOD(crypto_verify_16) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be two buffers");
    ARG_TO_UCHAR_BUFFER_LEN(string1, crypto_verify_16_BYTES);
    ARG_TO_UCHAR_BUFFER_LEN(string2, crypto_verify_16_BYTES);

    return 
        Napi::Number::New(env, crypto_verify_16(string1, string2));
}

// int crypto_verify_16(const unsigned char * string1, const unsigned char * string2)
NAPI_METHOD(crypto_verify_32) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be two buffers");
    ARG_TO_UCHAR_BUFFER_LEN(string1, crypto_verify_32_BYTES);
    ARG_TO_UCHAR_BUFFER_LEN(string2, crypto_verify_32_BYTES);

    return 
        Napi::Number::New(env, crypto_verify_32(string1, string2));
}

// int crypto_verify_64(const unsigned char * string1, const unsigned char * string2)
NAPI_METHOD(crypto_verify_64) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be two buffers");
    ARG_TO_UCHAR_BUFFER_LEN(string1, crypto_verify_64_BYTES);
    ARG_TO_UCHAR_BUFFER_LEN(string2, crypto_verify_64_BYTES);

    return 
        Napi::Number::New(env, crypto_verify_64(string1, string2));
}

/**
 * void sodium_increment(unsigned char *n, const size_t nlen);
 *
 */
NAPI_METHOD(increment) {
    Napi::Env env = info.Env();

    ARGS(1, "argument must be a buffer");
    ARG_TO_UCHAR_BUFFER(buffer);
    
    sodium_increment(buffer, buffer_size);

    return NAPI_NULL;
}

/**
 * int sodium_compare(const unsigned char *b1_, const unsigned char *b2, size_t len);
 */
NAPI_METHOD(compare) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be two buffers");
    ARG_TO_UCHAR_BUFFER(buffer_1);
    ARG_TO_UCHAR_BUFFER(buffer_2);

    if( buffer_1_size != buffer_2_size ) {
        Napi::Error::New(env, "buffers need to be the same size").ThrowAsJavaScriptException();
        return NAPI_NULL;
    }

    return 
        Napi::Number::New(env, sodium_compare(buffer_1, buffer_2, buffer_1_size));
}

/**
 * void sodium_add(unsigned char *a, const unsigned char *b, const size_t len);
 */
NAPI_METHOD(add) {
    Napi::Env env = info.Env();

    ARGS(2, "arguments must be two buffers");
    ARG_TO_UCHAR_BUFFER(buffer_1);
    ARG_TO_UCHAR_BUFFER(buffer_2);

    if( buffer_1_size != buffer_2_size ) {
        Napi::Error::New(env, "buffers need to be the same size").ThrowAsJavaScriptException();
        return NAPI_NULL;
    }
    sodium_add(buffer_1, buffer_2, buffer_1_size);
    return NAPI_NULL;
}

/**
 * `int sodium_is_zero(const unsigned char *n, const size_t nlen);
 */
NAPI_METHOD(is_zero) {
    Napi::Env env = info.Env();

    ARGS(1, "argument must be a buffer");
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
    EXPORT_INT(crypto_verify_16_BYTES);
    EXPORT_INT(crypto_verify_32_BYTES);
    EXPORT_INT(crypto_verify_64_BYTES);
    
    // Hexadecimal encoding/decoding
    EXPORT(bin2hex);
    EXPORT(hex2bin);
    
    // Large Numbers
    EXPORT(increment);
    EXPORT(add);
    EXPORT(compare);
    EXPORT(is_zero);
}