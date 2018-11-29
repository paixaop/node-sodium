/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __NODE_SODIUM_H__
#define __NODE_SODIUM_H__

#include <napi.h>
#include "sodium.h"

// As per Libsodium install docs
#define SODIUM_STATIC

// Check if a function argument is a node Buffer. If not throw V8 exception
#define ARG_IS_BUFFER(i, MSG) \
    if (!info[i].IsBuffer()) { \
        THROW_ERROR("argument " #MSG " must be a buffer"); \
    }

#define ARG_IS_BUFFER_OR_NULL(i, MSG) \
    if (!info[i].IsBuffer()) { \
        if( !info[i].IsNull() ) { \
            THROW_ERROR("argument " #MSG " must be a buffer"); \
        } \
    }

// Create a new buffer, and get a pointer to it
#define NEW_BUFFER_AND_PTR(NAME, size) \
    Napi::Buffer<unsigned char> NAME = Napi::Buffer<unsigned char>::New(info.Env(), size); \
    unsigned char* NAME ## _ptr = (unsigned char*) NAME.Data(); \
    if( *NAME ## _ptr == 0 ) { }

#define GET_ARG_AS(i, NAME, TYPE) \
    ARG_IS_BUFFER(i,#NAME); \
    Napi::Buffer<TYPE> NAME ## _buffer = info[i].As<Napi::Buffer<TYPE>>(); \
    TYPE *NAME = (TYPE *) NAME ## _buffer.Data(); \
    unsigned long long NAME ## _size = NAME ## _buffer.Length(); \
    if( NAME ## _size == 0 ) { }

#define GET_ARG_AS_OR_NULL(i, NAME, TYPE) \
    TYPE *NAME; \
    unsigned long long NAME ## _size = 0; \
    if( !info[i].IsNull() ) { \
        ARG_IS_BUFFER(i,#NAME); \
        Napi::Buffer<TYPE> NAME ## _buffer = info[i].As<Napi::Buffer<TYPE>>(); \
        NAME = (TYPE *) NAME ## _buffer.Data(); \
        NAME ## _size = NAME ## _buffer.Length(); \
        if( NAME ## _size == 0 ) { } \
    } else { \
        NAME = NULL; \
    }

#define GET_ARG_AS_LEN(i, NAME, MAXLEN, TYPE) \
    GET_ARG_AS(i, NAME, TYPE); \
    if( NAME ## _size != MAXLEN ) { \
        THROW_ERROR("argument " #NAME " must be " #MAXLEN " bytes long, but got a different value"); \
    }

#define GET_ARG_AS_NUMBER(i, NAME) \
    size_t NAME; \
    if (info[i].IsNumber()) { \
        NAME = info[i].As<Napi::Number>().Uint32Value(); \
    } else { \
        THROW_ERROR("argument " #NAME " must be a number"); \
    }

#define GET_ARG_AS_STRING(i, NAME) \
    Napi::String NAME; \
    if (info[i].IsString()) { \
        NAME = info[i].ToString(); \
    } else { \
        THROW_ERROR("argument " #NAME " must be a string"); \
    }

#define ARG_TO_NUMBER(NAME)                         GET_ARG_AS_NUMBER(_arg, NAME); _arg++
#define ARG_TO_STRING(NAME)                         GET_ARG_AS_STRING(_arg, NAME); _arg++;

#define ARG_TO_BUFFER_TYPE(NAME, TYPE)              GET_ARG_AS(_arg, NAME, TYPE); _arg++
#define ARG_TO_BUFFER_TYPE_LEN(NAME, MAXLEN, TYPE)  GET_ARG_AS_LEN(_arg, NAME, MAXLEN, TYPE); _arg++
#define ARG_TO_BUFFER_OR_NULL(NAME, TYPE)           GET_ARG_AS_OR_NULL(_arg, NAME, TYPE); _arg++
#define ARG_TO_UCHAR_BUFFER(NAME)                   GET_ARG_AS(_arg, NAME, unsigned char); _arg++
#define ARG_TO_UCHAR_BUFFER_LEN(NAME, MAXLEN)       GET_ARG_AS_LEN(_arg, NAME, MAXLEN, unsigned char); _arg++
#define ARG_TO_UCHAR_BUFFER_OR_NULL(NAME)           GET_ARG_AS_OR_NULL(_arg, NAME, unsigned char); _arg++

#define ARG_TO_UCHAR_BUFFER_LEN_OR_NULL(NAME, MAXLEN) \
    GET_ARG_AS_OR_NULL(_arg, NAME, unsigned char); \
    if( NAME ## _size != 0 && NAME ## _size != MAXLEN ) { \
        THROW_ERROR(#NAME " argument " #NAME " must be " #MAXLEN " bytes long or NULL"); \
    } \
    _arg++


#define CHECK_MAX_SIZE(NAME, MAX_SIZE)  \
    if( NAME > MAX_SIZE ) {     \
        THROW_ERROR(#NAME " length cannot be bigger than " #MAX_SIZE " bytes"); \
    }

#define CHECK_MIN_SIZE(NAME, MIN_SIZE)  \
    if( NAME < MIN_SIZE ) {     \
        THROW_ERROR(#NAME " length cannot be smaller than " #MIN_SIZE " bytes"); \
    }

#define CHECK_SIZE(NAME, MIN_SIZE, MAX_SIZE) \
    CHECK_MIN_SIZE(NAME, MIN_SIZE); \
    CHECK_MAX_SIZE(NAME, MAX_SIZE)

#define ARGS(n, message) \
    int _arg = 0;        \
    if (info.Length() < (n)) { \
        THROW_ERROR(message); \
    }

#define EXPORT_INT(NAME) \
    exports.DefineProperty( \
        Napi::PropertyDescriptor::Value( \
            Napi::String::New(env, #NAME), \
            Napi::Number::New(env, NAME), \
            napi_default \
        ) \
    )

#define EXPORT_STRING(NAME) \
    exports.DefineProperty( \
        Napi::PropertyDescriptor::Value( \
            Napi::String::New(env, #NAME), \
            Napi::String::New(env, NAME), \
            napi_default \
        ) \
    )
    
#define EXPORT(NAME) \
    exports.Set(Napi::String::New(env, #NAME), \
                Napi::Function::New(env, bind_ ## NAME ## _))

#define EXPORT_ALIAS(NAME, LINK_TO) \
    exports.Set(Napi::String::New(env, #NAME), \
                Napi::Function::New(env, bind_ ## LINK_TO ## _))

#define NAPI_METHOD(NAME) \
    Napi::Value bind_ ## NAME ## _(const Napi::CallbackInfo& info)

#define NAPI_METHOD_FROM_INT(NAME) \
    Napi::Value bind_ ## NAME ## _(const Napi::CallbackInfo& info) { \
        Napi::Env env = info.Env(); \
        return Napi::Number::New(env, NAME()); \
    }

#define NAPI_METHOD_FROM_STRING(NAME) \
    Napi::Value bind_ ## NAME ## _(const Napi::CallbackInfo& info) { \
        Napi::Env env = info.Env(); \
        return Napi::String::New(env, NAME()); \
    }


#define NAPI_METHOD_KEYGEN(NAME) \
    NAPI_METHOD(NAME ## _keygen) { \
        NEW_BUFFER_AND_PTR(buffer, NAME ## _KEYBYTES); \
        NAME ## _keygen(buffer_ptr); \
        return buffer; \
    }

#define NAPI_FALSE  Napi::Boolean::New(env, false)
#define NAPI_TRUE   Napi::Boolean::New(env, true)
#define NAPI_NULL   env.Null()

#define THROW_IF_ERR(ERR) \
    if ( (ERR) != 0 ) { \
        Napi::Error::New(env, "libsodium call failed").ThrowAsJavaScriptException(); \
        return NAPI_NULL; \
    }

#define THROW_ERROR(msg) \
    Napi::Error::New(env, (msg)).ThrowAsJavaScriptException(); \
    return NAPI_NULL; \


#endif
