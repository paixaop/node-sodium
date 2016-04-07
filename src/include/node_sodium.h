/**
 * Node Native Module for Lib Sodium
 *
 * @Author Pedro Paixao
 * @email paixaop at gmail dot com
 * @License MIT
 */
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

// Create a new buffer, and get a pointer to it
#define NEW_BUFFER_AND_PTR(name, size) \
    Local<Object> name = Nan::NewBuffer(size).ToLocalChecked(); \
    unsigned char* name ## _ptr = (unsigned char*)Buffer::Data(name)

#define GET_ARG_AS(i, NAME, TYPE) \
    ARG_IS_BUFFER(i,#NAME); \
    TYPE NAME = (TYPE) Buffer::Data(info[i]->ToObject()); \
    unsigned long long NAME ## _size = Buffer::Length(info[i]->ToObject()); \
    if( NAME ## _size == 0 ) { \
        std::ostringstream oss; \
        oss << "argument " << #NAME << " length cannot be zero" ; \
        return Nan::ThrowError(oss.str().c_str()); \
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
        NAME = info[i]->Int32Value(); \
    } else { \
        return Nan::ThrowError("argument size must be a number"); \
    }

#define GET_ARG_POSITIVE_NUMBER(i, NAME) \
    GET_ARG_NUMBER(i, NAME); \
    if( NAME < 0 ) { \
        return Nan::ThrowError("argument size must be a positive number"); \
    }

#define NUMBER_OF_MANDATORY_ARGS(n, message) \
    if (info.Length() < (n)) {               \
        return Nan::ThrowError(message);       \
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