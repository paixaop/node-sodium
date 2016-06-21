/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
#ifndef __NODE_SODIUM_H__
#define __NODE_SODIUM_H__

#include <node.h>
#include <node_buffer.h>

#include <cstdlib>
#include <ctime>
#include <cstring>
#include <string>
#include <sstream>

#include <nan.h>

#include "sodium.h"

using namespace node;
using namespace v8;

// As per Libsodium install docs
#define SODIUM_STATIC

// Check if a function argument is a node Buffer. If not throw V8 exception
#define ARG_IS_BUFFER(i,msg) \
    if (!Buffer::HasInstance(info[i])) { \
        std::ostringstream oss; \
        oss << "argument " << msg << " must be a buffer"; \
        return Nan::ThrowError(oss.str().c_str()); \
    }

#define ARG_IS_BUFFER_OR_NULL(i,msg) \
    if (!Buffer::HasInstance(info[i])) { \
        if( !info[i]->IsNull() ) { \
            std::ostringstream oss; \
            oss << "argument " << msg << " must be a buffer"; \
            return Nan::ThrowError(oss.str().c_str()); \
        } \
    }

// Create a new buffer, and get a pointer to it
#define NEW_BUFFER_AND_PTR(name, size) \
    Local<Object> name = Nan::NewBuffer(size).ToLocalChecked(); \
    unsigned char* name ## _ptr = (unsigned char*)Buffer::Data(name)

#define GET_ARG_AS(i, NAME, TYPE) \
    ARG_IS_BUFFER(i,#NAME); \
    TYPE NAME = (TYPE) Buffer::Data(info[i]->ToObject()); \
    unsigned long long NAME ## _size = Buffer::Length(info[i]->ToObject()); \
    if( NAME ## _size == 0 ) { }

#define GET_ARG_AS_OR_NULL(i, NAME, TYPE) \
    TYPE NAME; \
    unsigned long long NAME ## _size = 0; \
    if( !info[i]->IsNull() ) { \
        ARG_IS_BUFFER(i,#NAME); \
        NAME = (TYPE) Buffer::Data(info[i]->ToObject()); \
        NAME ## _size = Buffer::Length(info[i]->ToObject()); \
        if( NAME ## _size == 0 ) { } \
    } else { \
        NAME = NULL; \
    }

#define GET_ARG_AS_LEN(i, NAME, MAXLEN, TYPE) \
    GET_ARG_AS(i, NAME, TYPE); \
    if( NAME ## _size != MAXLEN ) { \
        std::ostringstream oss; \
        oss << "argument " << #NAME << " must be " << MAXLEN << " bytes long" ; \
        return Nan::ThrowError(oss.str().c_str()); \
    }

#define GET_ARG_AS_UCHAR(i, NAME) \
    GET_ARG_AS(i, NAME, unsigned char*)

#define GET_ARG_AS_UCHAR_LEN(i, NAME, MAXLEN) \
    GET_ARG_AS_LEN(i, NAME, MAXLEN, unsigned char*)

#define GET_ARG_AS_VOID(i, NAME) \
    GET_ARG_AS(i, NAME, void*)

#define GET_ARG_AS_VOID_LEN(i, NAME, MAXLEN) \
    GET_ARG_AS_LEN(i, NAME, MAXLEN, void*)

#define GET_ARG_NUMBER(i, NAME) \
    size_t NAME; \
    if (info[i]->IsUint32()) { \
        NAME = info[i]->Uint32Value(); \
    } else { \
        return Nan::ThrowError("argument size must be a number"); \
    }

#define ARG_TO_BUFFER_TYPE(NAME, TYPE)              GET_ARG_AS(_arg, NAME, TYPE); _arg++
#define ARG_TO_BUFFER_TYPE_LEN(NAME, MAXLEN, TYPE)  GET_ARG_AS_LEN(_arg, NAME, MAXLEN, TYPE); _arg++
#define ARG_TO_NUMBER(NAME)                         GET_ARG_NUMBER(_arg, NAME); _arg++
#define ARG_TO_VOID_BUFFER_LEN(NAME, MAXLEN)        GET_ARG_AS_VOID_LEN(_arg, NAME, MAXLEN); _arg++
#define ARG_TO_VOID_BUFFER(NAME)                    GET_ARG_AS_VOID(_arg, NAME); _arg++
#define ARG_TO_UCHAR_BUFFER(NAME)                   GET_ARG_AS_UCHAR(_arg, NAME); _arg++
#define ARG_TO_UCHAR_BUFFER_LEN(NAME, MAXLEN)       GET_ARG_AS_UCHAR_LEN(_arg, NAME, MAXLEN); _arg++
#define ARG_TO_BUFFER_OR_NULL(NAME, TYPE)           GET_ARG_AS_OR_NULL(_arg, NAME, TYPE); _arg++
#define ARG_TO_UCHAR_BUFFER_OR_NULL(NAME)           GET_ARG_AS_OR_NULL(_arg, NAME, unsigned char*); _arg++

#define ARG_TO_UCHAR_BUFFER_LEN_OR_NULL(NAME, MAXLEN) \
    GET_ARG_AS_OR_NULL(_arg, NAME, unsigned char*); \
    if( NAME ## _size != 0 && NAME ## _size != MAXLEN ) { \
        std::ostringstream oss; \
        oss << "argument " << #NAME << " must be " << MAXLEN << " bytes long or NULL" ; \
        return Nan::ThrowError(oss.str().c_str()); \
    } \
    _arg++


#define CHECK_MAX_SIZE(NAME, MAX_SIZE)  \
    if( NAME > MAX_SIZE ) {     \
        std::ostringstream oss; \
        oss << #NAME << " size cannot be bigger than " << MAX_SIZE << " bytes";  \
        return Nan::ThrowError(oss.str().c_str()); \
    }

#define CHECK_MIN_SIZE(NAME, MIN_SIZE)  \
    if( NAME < MIN_SIZE ) {     \
        std::ostringstream oss; \
        oss << #NAME << " size cannot be smaller than " << MIN_SIZE << " bytes";  \
        return Nan::ThrowError(oss.str().c_str()); \
    }

#define CHECK_SIZE(NAME, MIN_SIZE, MAX_SIZE) \
    CHECK_MIN_SIZE(NAME, MIN_SIZE); \
    CHECK_MAX_SIZE(NAME, MAX_SIZE)

#define ARGS(n, message) \
    int _arg = 0;        \
    NUMBER_OF_MANDATORY_ARGS(n, message)

#define NUMBER_OF_MANDATORY_ARGS(n, message) \
    if (info.Length() < (n)) {               \
        return Nan::ThrowError(message);     \
    }

#define TO_REAL_BUFFER(slowBuffer, actualBuffer) \
    Handle<Value> constructorArgs ## slowBuffer[3] = \
        { slowBuffer->handle_, \
          Nan::New<Integer>(Buffer::Length(slowBuffer)), \
          Nan::New<Integer>(0) }; \
    Local<Object> actualBuffer = bufferConstructor->NewInstance(3, constructorArgs ## slowBuffer);

#define NEW_INT_PROP(NAME) \
    Nan::ForceSet(target, Nan::New<String>(#NAME).ToLocalChecked(), Nan::New<Integer>(NAME), v8::ReadOnly);

#define NEW_NUMBER_PROP(NAME) \
    Nan::ForceSet(target, Nan::New<String>(#NAME).ToLocalChecked(), Nan::New<Number>(NAME), v8::ReadOnly);

#define NEW_STRING_PROP(NAME) \
    Nan::ForceSet(target, Nan::New<String>(#NAME).ToLocalChecked(), Nan::New<String>(NAME).ToLocalChecked(), v8::ReadOnly);

#define NEW_METHOD(NAME) \
    Nan::SetMethod(target, #NAME, bind_ ## NAME)

#define NEW_METHOD_ALIAS(NAME, LINKTO) \
    Nan::SetMethod(target, #NAME, bind_ ## LINKTO)

#endif