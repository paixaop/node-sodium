#Low Level API

## Usage
The low level `libsodium` API is available directly in `node-sodium` by using the `.api` object. Through it you can access all the functions [ported](./ported-functions.md) from `libsodium` wihtout the use of the high level Javascript API. This will feel familiar for developers that are used to work with `libsodium` in other languages. It also gives you the chance to workaround any possible bugs on the higher level APIs.

If you're going to use the low level API you should do the following:

```javascript
var sodium = require('sodium').api;

// example of calling crypto_box_keypair
var version = sodium.sodium_version_string();

// getting a random number using libsodium PRNG
var num = sodium.randombytes_random();
```

The object `sodium` includes all the API calls. All code examples in this document assume that you have `var sodium = require('sodium').api;` somewhere in your code, before you call any API functions

## Version Functions
Report the version fo the Libsodium library

### sodium_version_string ( )
---

Get full version number of libsodium compiled with which node-sodium was compiled

**Returns**:

  * String with full lib sodium version. Example `0.4.5`
  
**Example**:
  
```javascript 
var version = sodium.sodium_version_string();
console.log(version);  // output should be 0.4.5 or similar
```
  
### sodium_library_version_minor ( )
---
	
Get the minor version number of libsodium with which node-sodium was compiled. If the full version string is `0.4.5` this function will return `5`.

**Returns**:

  * **Number** of minor lib sodium version 

**Example**:
  
```javascript 
var minor_version = sodium.sodium_library_version_minor();
console.log(minor_version);  // output should be 5 or similar
```  

  
### sodium_library_version_major ( )
---

Get the major version number of libsodium with which node-sodium was compiled. If the full version string is `0.4.5` this function will return `4`.

**Returns**:

  * **Number** of major lib sodium version
  
**Example**:
  
```javascript 
var major_version = sodium.sodium_library_version_major();
console.log(major_version);  // output should be 5 or similar
``` 
  
## Utilities

### memzero (buffer)
---

Securely wipe buffer

Parameters:

  * `buffer` buffer to wipe


### memcmp (buffer1, buffer2, size)

Compare buffers in constant time

Parameters:

  * `buffer1` buffer you wish to compare with `buffer2`
  * `buffer2` buffer you wish to compare with `buffer1`
  * `size` number of bytes to compare
  
Returns:

  * `0` if `size` bytes of `buffer1` and `buffer2` are equal
  * another value if they are not


### crypto_verify_16 (buffer1, buffer2)

Compares the first crypto_verify_16_BYTES of the given strings.

Parameters:

  * `buffer1` buffer you wish to compare with `buffer2`
  * `buffer2` buffer you wish to compare with `buffer1`
  
Returns:

  * `0` if `size` bytes of `buffer1` and `buffer2` are equal
  * another value if they are not


### crypto_verify_32 (buffer1, buffer2)

Compares the first crypto_verify_32_BYTES of the given strings.

Parameters:

  * `buffer1` buffer you wish to compare with `buffer2`
  * `buffer2` buffer you wish to compare with `buffer1`
  
Returns:

  * `0` if `size` bytes of `buffer1` and `buffer2` are equal
  * another value if they are not
  
## Random 
### randombytes_buf (buffer)
Fill the specified buffer with size random bytes. 

Parameters:

  * `buffer` buffer to fill with random data
  
### randombytes_close ()
Close the file descriptor or the handle for the cryptographic service provider. 

### randombytes_stir ()
Generate a new key for the pseudorandom number generator. 

### randombytes_random ()
Returns

  * random 32-bit unsigned value. 

### randombytes_uniform (upperBound)
Returns

  * numeric value between `0` and `upperBound` using a uniform distribution.
