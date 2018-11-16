/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

// int sodium_runtime_has_aesni(void);
Napi::Value bind_sodium_runtime_has_aesni(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_aesni());
}

//int sodium_runtime_has_neon(void);
Napi::Value bind_sodium_runtime_has_neon(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_neon());
}

//int sodium_runtime_has_sse2(void);
Napi::Value bind_sodium_runtime_has_sse2(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_sse2());
}

//int sodium_runtime_has_sse3(void);
Napi::Value bind_sodium_runtime_has_sse3(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_sse3());
}

//int sodium_runtime_has_ssse3(void);
Napi::Value bind_sodium_runtime_has_ssse3(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_ssse3());
}

//int sodium_runtime_has_sse41(void);
Napi::Value bind_sodium_runtime_has_sse41(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_sse41());
}

//int sodium_runtime_has_avx(void);
Napi::Value bind_sodium_runtime_has_avx(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_avx());
}

//int sodium_runtime_has_avx2(void);
Napi::Value bind_sodium_runtime_has_avx2(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_avx2());
}

//int sodium_runtime_has_pclmul(void);
Napi::Value bind_sodium_runtime_has_pclmul(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    return 
        Napi::Number::New(env, sodium_runtime_has_pclmul());
}

/**
 * Register function calls in node binding
 */
void register_runtime(Napi::Env env, Napi::Object exports) {

    NEW_METHOD(sodium_runtime_has_aesni);
    NEW_METHOD(sodium_runtime_has_avx);
    NEW_METHOD(sodium_runtime_has_avx2);
    NEW_METHOD(sodium_runtime_has_neon);
    NEW_METHOD(sodium_runtime_has_pclmul);
    NEW_METHOD(sodium_runtime_has_sse2);
    NEW_METHOD(sodium_runtime_has_sse3);
    NEW_METHOD(sodium_runtime_has_sse41);
    NEW_METHOD(sodium_runtime_has_ssse3);
}