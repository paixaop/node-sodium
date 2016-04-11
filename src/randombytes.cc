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
NAN_METHOD(bind_randombytes_buf) {
    Nan::EscapableHandleScope scope;

    NUMBER_OF_MANDATORY_ARGS(1,"argument must be a buffer");

    GET_ARG_AS_VOID(0, buffer);
    randombytes_buf(buffer, buffer_size);

    return info.GetReturnValue().Set(Nan::Null());
}

// void randombytes_stir()
NAN_METHOD(bind_randombytes_stir) {
    Nan::EscapableHandleScope scope;
    randombytes_stir();

    return info.GetReturnValue().Set(Nan::Null());
}

NAN_METHOD(bind_randombytes_close) {
    Nan::EscapableHandleScope scope;

    // int randombytes_close()
    return info.GetReturnValue().Set(
        Nan::New<Integer>(randombytes_close())
    );
}

NAN_METHOD(bind_randombytes_random) {
    Nan::EscapableHandleScope scope;

    // uint_32 randombytes_random()
    return info.GetReturnValue().Set(
        Nan::New<Int32>(randombytes_random())
    );
}

NAN_METHOD(bind_randombytes_uniform) {
    Nan::EscapableHandleScope scope;
    uint32_t upper_bound;

    NUMBER_OF_MANDATORY_ARGS(1,"argument size must be a positive number");

    if (info[0]->IsUint32()) {
        upper_bound = info[0]->Int32Value();
    } else {
        return Nan::ThrowError("argument size must be a positive number");
    }

    // uint32_t randombytes_uniform(const uint32_t upper_bound)
    return info.GetReturnValue().Set(
        Nan::New<Int32>(randombytes_uniform(upper_bound))
    );
}

/**
 * Register function calls in node binding
 */
void register_randombytes(Handle<Object> target) {
   
    NEW_METHOD(randombytes_buf);
    Nan::SetMethod(target, "randombytes", bind_randombytes_buf);
    NEW_METHOD(randombytes_close);
    NEW_METHOD(randombytes_stir);
    NEW_METHOD(randombytes_random);
    NEW_METHOD(randombytes_uniform);
    
}