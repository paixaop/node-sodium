#Low Level API

# Usage
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

# Version Functions
Report the version fo the Libsodium library

## sodium_version_string()

Get full version number of libsodium compiled with which node-sodium was compiled

**Returns**:

  * String with full lib sodium version. Example `0.4.5`
  
**Example**:
  
```javascript 
var version = sodium.sodium_version_string();
console.log(version);  // output should be 0.4.5 or similar
```
  
## sodium_library_version_minor()
	
Get the minor version number of libsodium with which node-sodium was compiled. If the full version string is `0.4.5` this function will return `5`.

**Returns**:

  * **Number** of minor lib sodium version 

**Example**:
  
```javascript 
var minor_version = sodium.sodium_library_version_minor();
console.log(minor_version);  // output should be 5 or similar
```  

  
## sodium_library_version_major()

Get the major version number of libsodium with which node-sodium was compiled. If the full version string is `0.4.5` this function will return `4`.

**Returns**:

  * **Number** of major lib sodium version
  
**Example**:
  
```javascript 
var major_version = sodium.sodium_library_version_major();
if( major_version < 4) {
    console.log("Unsupported version");  // output should be 5 or similar
}
``` 
  
# Utility Functions

## memzero(buffer)

Securely wipe buffer

**Parameters**:

  * **Buffer** buffer to wipe

**Example**:
  
```javascript
// Lets create a new buffer with a string
var buffer = new Buffer("I am a buffer", "utf-8");
console.log(b);            // <Buffer 49 20 61 6d 20 61 20 62 75 66 66 65 72> 
console.log(b.toString()); // I'm a string! will be printed

// Now lets set all the bytes in the buffer to 0
sodium.memzero(b);
console.log(b);            // <Buffer 00 00 00 00 00 00 00 00 00 00 00 00 00>
``` 

### memcmp(buffer1, buffer2, size)

Compare buffers in constant time

**Parameters**:

  * `buffer1` buffer you wish to compare with `buffer2`
  * `buffer2` buffer you wish to compare with `buffer1`
  * `size` number of bytes to compare
  
**Returns**:

  * `0` if `size` bytes of `buffer1` and `buffer2` are equal
  * another value if they are not

**Example**:

```
// Create the test buffers
var buffer1 = new Buffer("I am a buffer", "utf-8");
var buffer2 = new Buffer("I am a buffer too", "utf-8");

// Compare the two buffers for full length of the buffer1
if( sodium.memcmp(buffer1, buffer2, buffer1.length) == 0 ) {

	// This will print as the first 13 bytes of 
	// buffer1 are equal to buffer2
	console.log("Buffers are equal")
}
```

## crypto_verify_16(buffer1, buffer2)

Compares the first 16 of the given buffers.

**Parameters**:

  * `buffer1` buffer you wish to compare with `buffer2`
  * `buffer2` buffer you wish to compare with `buffer1`
  
**Returns**:

  * `0` if first 16 bytes of `buffer1` and `buffer2` are equal
  * another value if they are not
  
This function is equivalent of calling `memcmp(buffer1, buffer2, 16)`

**Example**

```javascript
var b1= new Buffer([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
var b2= new Buffer([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 18, 19, 20]);

if( sodium.crypto_verify_16(b1, b2) != 0 ) {
	console.log('buffers are different');
}
```


## crypto_verify_32(buffer1, buffer2)

Compares the first 32 of the given buffers.

**Parameters**:

  * `buffer1` buffer you wish to compare with `buffer2`
  * `buffer2` buffer you wish to compare with `buffer1`
  
**Returns**:

  * `0` if first 32 bytes of `buffer1` and `buffer2` are equal
  * another value if they are not
  
This function is equivalent of calling `memcmp(buffer1, buffer2, 32)`

**See Also**:

  * [memcmp](#memcmp)
  * [crypto_verify_16](#crypto_verify_16)
  
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
