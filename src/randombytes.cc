/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#include "node_sodium.h"

// Generating Random Data
// Docs: https://download.libsodium.org/doc/generating_random_data/index.html

// Lib Sodium Random

// void randombytes_buf(void *const buf, const size_t size)
Napi::Value bind_randombytes_buf(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(1,"argument must be a buffer");

    ARG_TO_UCHAR_BUFFER(buffer);
    randombytes_buf(buffer, buffer_size);

    return env.Null();
}

// void randombytes_stir()
Napi::Value bind_randombytes_stir(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    randombytes_stir();

    return env.Null();
}

Napi::Value bind_randombytes_close(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // int randombytes_close()
    return 
        Napi::Number::New(env, randombytes_close());
}

Napi::Value bind_randombytes_random(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    // uint_32 randombytes_random()
    return 
        Napi::Value::From(env, randombytes_random());
}

Napi::Value bind_randombytes_uniform(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ARGS(1,"argument size must be a positive number");
    ARG_TO_NUMBER(upper_bound);

    // uint32_t randombytes_uniform(const uint32_t upper_bound)
    return 
        Napi::Value::From(env, randombytes_uniform(upper_bound));
}

/*
Napi::Value bind_randombytes_keygen(const Napi::CallbackInfo& info) {
    NEW_BUFFER_AND_PTR(buffer, randombytes_SEEDBYTES);
    randombytes_keygen(buffer_ptr);
    return buffer;
}
*/

Napi::Value bind_randombytes_buf_deterministic(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    
    ARGS(2,"arguments buf and seed must be buffers");
    ARG_TO_UCHAR_BUFFER(buffer);
    ARG_TO_UCHAR_BUFFER_LEN(seed, randombytes_SEEDBYTES);
    randombytes_buf_deterministic(buffer, buffer_size, seed);
    return env.Null();
}

/**
 * Register function calls in node binding
 */
void register_randombytes(Napi::Env env, Napi::Object exports) {
   
    EXPORT(randombytes_buf);
    EXPORT_ALIAS(randombytes, randombytes_buf);
    EXPORT(randombytes_close);
    EXPORT(randombytes_stir);
    EXPORT(randombytes_random);
    EXPORT(randombytes_uniform);
    EXPORT(randombytes_buf_deterministic);

    NEW_INT_PROP(randombytes_SEEDBYTES);
}