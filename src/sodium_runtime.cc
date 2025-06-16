/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

// int sodium_runtime_has_aesni(void);
NAPI_METHOD(sodium_runtime_has_aesni) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_aesni());
}

//int sodium_runtime_has_neon(void);
NAPI_METHOD(sodium_runtime_has_neon) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_neon());
}

//int sodium_runtime_has_sse2(void);
NAPI_METHOD(sodium_runtime_has_sse2) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_sse2());
}

//int sodium_runtime_has_sse3(void);
NAPI_METHOD(sodium_runtime_has_sse3) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_sse3());
}

//int sodium_runtime_has_ssse3(void);
NAPI_METHOD(sodium_runtime_has_ssse3) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_ssse3());
}

//int sodium_runtime_has_sse41(void);
NAPI_METHOD(sodium_runtime_has_sse41) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_sse41());
}

//int sodium_runtime_has_avx(void);
NAPI_METHOD(sodium_runtime_has_avx) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_avx());
}

//int sodium_runtime_has_avx2(void);
NAPI_METHOD(sodium_runtime_has_avx2) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_avx2());
}

//int sodium_runtime_has_pclmul(void);
NAPI_METHOD(sodium_runtime_has_pclmul) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_pclmul());
}

/**
 * Register function calls in node binding
 */
void register_runtime(Napi::Env env, Napi::Object exports) {

    EXPORT(sodium_runtime_has_aesni);
    EXPORT(sodium_runtime_has_avx);
    EXPORT(sodium_runtime_has_avx2);
    EXPORT(sodium_runtime_has_neon);
    EXPORT(sodium_runtime_has_pclmul);
    EXPORT(sodium_runtime_has_sse2);
    EXPORT(sodium_runtime_has_sse3);
    EXPORT(sodium_runtime_has_sse41);
    EXPORT(sodium_runtime_has_ssse3);
}