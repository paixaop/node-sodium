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
#include <uv.h>
#include <node_buffer.h>

#include <cstdlib>
#include <ctime>
#include <cstring>
#include <string>
#include <sstream>


#include "sodium.h"

using namespace Napi;

// As per Libsodium install docs
#define SODIUM_STATIC

// Check if a function argument is a node Buffer. If not throw V8 exception
#define ARG_IS_BUFFER(i,msg) \
    if (!info[i].IsBuffer()) { \
        std::ostringstream oss; \
        oss << "argument " << msg << " must be a buffer"; \
        Napi::Error::New(env, oss.str().c_str()).ThrowAsJavaScriptException(); \
        return env.Null(); \
    }

#define ARG_IS_BUFFER_OR_NULL(i,msg) \
    if (!info[i].IsBuffer()) { \
        if( !info[i].IsNull() ) { \
            std::ostringstream oss; \
            oss << "argument " << msg << " must be a buffer"; \
            Napi::Error::New(env, oss.str().c_str()).ThrowAsJavaScriptException(); \
            return env.Null(); \
        } \
    }

// Create a new buffer, and get a pointer to it
#define NEW_BUFFER_AND_PTR(NAME, size) \
    Napi::Buffer<unsigned char> NAME = Napi::Buffer<unsigned char>::New(info.Env(), size); \
    unsigned char* NAME ## _ptr = (unsigned char*) NAME.Data()

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
        std::ostringstream oss; \
        oss << "argument " << #NAME << " must be " << MAXLEN << " bytes long, but got " << NAME ## _size ; \
        Napi::Error::New(env, oss.str().c_str()).ThrowAsJavaScriptException(); \
        return env.Null(); \
    }

#define GET_ARG_AS_UCHAR(i, NAME) \
    GET_ARG_AS(i, NAME, unsigned char)

#define GET_ARG_AS_UCHAR_LEN(i, NAME, MAXLEN) \
    GET_ARG_AS_LEN(i, NAME, MAXLEN, unsigned char)

#define GET_ARG_AS_VOID(i, NAME) \
    GET_ARG_AS(i, NAME, void)

#define GET_ARG_AS_VOID_LEN(i, NAME, MAXLEN) \
    GET_ARG_AS_LEN(i, NAME, MAXLEN, void)

#define GET_ARG_NUMBER(i, NAME) \
    size_t NAME; \
    if (info[i].IsNumber()) { \
        NAME = info[i].As<Napi::Number>().Uint32Value(); \
    } else { \
        Napi::Error::New(env, "argument size must be a number").ThrowAsJavaScriptException(); \
        return env.Null(); \
    }

#define GET_ARG_AS_STRING(i, NAME) \
    Napi::String NAME; \
    if (info[i].IsString()) { \
        NAME = info[i].ToString(); \
    } else { \
        Napi::Error::New(env, "argument must be a string").ThrowAsJavaScriptException(); \
        return env.Null(); \
    }

#define ARG_TO_BUFFER_TYPE(NAME, TYPE)              GET_ARG_AS(_arg, NAME, TYPE); _arg++
#define ARG_TO_BUFFER_TYPE_LEN(NAME, MAXLEN, TYPE)  GET_ARG_AS_LEN(_arg, NAME, MAXLEN, TYPE); _arg++
#define ARG_TO_NUMBER(NAME)                         GET_ARG_NUMBER(_arg, NAME); _arg++
#define ARG_TO_VOID_BUFFER_LEN(NAME, MAXLEN)        GET_ARG_AS_VOID_LEN(_arg, NAME, MAXLEN); _arg++
#define ARG_TO_VOID_BUFFER(NAME)                    GET_ARG_AS_VOID(_arg, NAME); _arg++
#define ARG_TO_UCHAR_BUFFER(NAME)                   GET_ARG_AS_UCHAR(_arg, NAME); _arg++
#define ARG_TO_UCHAR_BUFFER_LEN(NAME, MAXLEN)       GET_ARG_AS_UCHAR_LEN(_arg, NAME, MAXLEN); _arg++
#define ARG_TO_BUFFER_OR_NULL(NAME, TYPE)           GET_ARG_AS_OR_NULL(_arg, NAME, TYPE); _arg++
#define ARG_TO_UCHAR_BUFFER_OR_NULL(NAME)           GET_ARG_AS_OR_NULL(_arg, NAME, unsigned char); _arg++
#define ARG_TO_STRING(NAME)                         GET_ARG_AS_STRING(_arg, NAME); _arg++;

#define ARG_TO_UCHAR_BUFFER_LEN_OR_NULL(NAME, MAXLEN) \
    GET_ARG_AS_OR_NULL(_arg, NAME, unsigned char); \
    if( NAME ## _size != 0 && NAME ## _size != MAXLEN ) { \
        std::ostringstream oss; \
        oss << "argument " << #NAME << " must be " << MAXLEN << " bytes long or NULL" ; \
        Napi::Error::New(env, oss.str().c_str()).ThrowAsJavaScriptException(); \
        return env.Null(); \
    } \
    _arg++


#define CHECK_MAX_SIZE(NAME, MAX_SIZE)  \
    if( NAME > MAX_SIZE ) {     \
        std::ostringstream oss; \
        oss << #NAME << " size cannot be bigger than " << MAX_SIZE << " bytes";  \
        Napi::Error::New(env, oss.str().c_str()).ThrowAsJavaScriptException(); \
        return env.Null(); \
    }

#define CHECK_MIN_SIZE(NAME, MIN_SIZE)  \
    if( NAME < MIN_SIZE ) {     \
        std::ostringstream oss; \
        oss << #NAME << " size cannot be smaller than " << MIN_SIZE << " bytes";  \
        Napi::Error::New(env, oss.str().c_str()).ThrowAsJavaScriptException(); \
        return env.Null(); \
    }

#define CHECK_SIZE(NAME, MIN_SIZE, MAX_SIZE) \
    CHECK_MIN_SIZE(NAME, MIN_SIZE); \
    CHECK_MAX_SIZE(NAME, MAX_SIZE)

#define ARGS(n, message) \
    int _arg = 0;        \
    NUMBER_OF_MANDATORY_ARGS(n, message)

#define NUMBER_OF_MANDATORY_ARGS(n, message) \
    if (info.Length() < (n)) {               \
        Napi::Error::New(env, message).ThrowAsJavaScriptException(); \
        return env.Null();     \
    }

#define TO_REAL_BUFFER(slowBuffer, actualBuffer) \
    Handle<Value> constructorArgs ## slowBuffer[3] = \
        { slowBuffer->handle_, \
          Napi::Number::New(env, Buffer::Length(slowBuffer)), \
          Napi::Number::New(env, 0) }; \
    Napi::Object actualBuffer = bufferConstructor->NewInstance(3, constructorArgs ## slowBuffer);

#define NEW_INT_PROP(NAME) \
    exports.DefineProperty( \
        Napi::PropertyDescriptor::Value( \
            Napi::String::New(env, #NAME), \
            Napi::Number::New(env, NAME), \
            napi_default \
        ) \
    )

#define NEW_NUMBER_PROP(NAME) \
     exports.DefineProperty( \
        Napi::PropertyDescriptor::Value( \
            Napi::String::New(env, #NAME), \
            Napi::Number::New(env, NAME), \
            napi_default \
        ) \
    )

#define NEW_STRING_PROP(NAME) \
    exports.DefineProperty( \
        Napi::PropertyDescriptor::Value( \
            Napi::String::New(env, #NAME), \
            Napi::String::New(env, NAME), \
            napi_default \
        ) \
    )
    
#define NEW_METHOD(NAME) \
    exports.Set(Napi::String::New(env, #NAME), \
                Napi::Function::New(env, bind_ ## NAME))

#define NEW_METHOD_ALIAS(NAME, LINK_TO) \
    exports.Set(Napi::String::New(env, #NAME), \
                Napi::Function::New(env, bind_ ## LINK_TO))

#define NAPI_METHOD(name) \
    Napi::Value name(const Napi::CallbackInfo& info)

#endif