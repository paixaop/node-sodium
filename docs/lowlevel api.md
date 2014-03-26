#Low Level API
Parts of this document are copied from [NaCl librarby Documentation](http://nacl.cr.yp.to/index.html) by Daniel J. Bernstein, author of the great NaCl library which is the base of `libsodium`, and therefore `node-sodium`.

# API Usage
The low level `libsodium` API is available directly in `node-sodium` by using the `.api` object. Through it you can access all the functions [ported](./ported-functions.md) from `libsodium` wihtout the use of the high level Javascript API. This will feel familiar for developers that are used to work with `libsodium` in other languages. It also gives you the chance to workaround any possible bugs on the higher level APIs.

If you're going to use the low level API you should do the following:

```javascript
var sodium = require('sodium').api;

// example of calling crypto_box_keypair
var version = sodium.sodium_version_string();

// getting a random number using libsodium PRNG
var num = sodium.randombytes_random();
```

The object `sodium` includes all the API calls. All code examples in this document assume that you have `var sodium = require('sodium').api;` somewhere in your code, before you call any API functions.

# Async Interface
At this time `node-sodium` only provides sync interface for low level API calls.

# Version Functions
Report the version fo the Libsodium library

## sodium_version_string()

Get full version number of libsodium compiled with which node-sodium was compiled

**Returns**:

  * **{String}** with full lib sodium version. Example `0.4.5`
  
**Example**:
  
```javascript 
var version = sodium.sodium_version_string();
console.log(version);  // output should be 0.4.5 or similar
```
  
## sodium_library_version_minor()
	
Get the minor version number of libsodium with which node-sodium was compiled. If the full version string is `0.4.5` this function will return `5`.

**Returns**:

  * **{Number}** of minor lib sodium version 

**Example**:
  
```javascript 
var minor_version = sodium.sodium_library_version_minor();
console.log(minor_version);  // output should be 5 or similar
```  

  
## sodium_library_version_major()

Get the major version number of libsodium with which node-sodium was compiled. If the full version string is `0.4.5` this function will return `4`.

**Returns**:

  * **{Number}** of major lib sodium version
  
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

  * **{Buffer}** `buffer` to wipe

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

## memcmp(buffer1, buffer2, size)

Compare buffers in constant time

**Parameters**:

  * **{Buffer}** `buffer1` you wish to compare with `buffer2`
  * **{Buffer}** `buffer2`
  * **{Number}** `size` number of bytes to compare
  
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

  * **{Buffer}** `buffer1` buffer you wish to compare with `buffer2`
  * **{Buffer}** `buffer2` 
  
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

**See Also**:

  * [memcmp](#memcmpbuffer1-buffer2-size)
  * [crypto_verify_32](#crypto_verify_32buffer1-buffer2)
    

## crypto_verify_32(buffer1, buffer2)

Compares the first 32 of the given buffers.

**Parameters**:

  * **{Buffer}** `buffer1` you wish to compare with `buffer2`
  * **{Buffer}** `buffer2`
  
**Returns**:

  * `0` if first 32 bytes of `buffer1` and `buffer2` are equal
  * another value if they are not
  
This function is equivalent of calling `memcmp(buffer1, buffer2, 32)`

**See Also**:

  * [memcmp](#memcmpbuffer1-buffer2-size)
  * [crypto_verify_16](#crypto_verify_16buffer1-buffer2)
  
## sodium_bin2hex()
Use node's native `Buffer.toString()` method instead

  
# Random Numbers
Internal random number generator functions. Random numbers are a critical part of any encryption system. It is recomended that you use `libsodium` random number API, instead of the default javascript provided functions.

## randombytes(buffer)
Fill the specified buffer with size random bytes. Same as `randombytes_buf()`

**Parameters**:

  * **{Buffer}** `buffer` to fill with random data
  
**Example**:

```javascript
// Create a nonce
var b = new Buffer(32);
sodium.randombytes(b,32);
```

**See Also**:
  * [randombytes_buf](#randombytes_bufbuffer)

## randombytes_buf(buffer)
Fill the specified buffer with size random bytes. Same as `randombytes()`

**Parameters**:

  * **{Buffer}** `buffer` to fill with random data
  
**Example**:

```javascript
// Create a nonce
var b = new Buffer(32);
sodium.randombytes_buf(b,32);
```

**See Also**:
  * [randombytes](#randombytesbuffer)

  
## randombytes_close()
Close the file descriptor or the handle for the cryptographic service provider. 

## randombytes_stir()
Generate a new key for the pseudorandom number generator. 

## randombytes_random()
Generate a 32-bit unsigned random number

**Returns**:

  * **{Number}** random 32-bit unsigned value. 

## randombytes_uniform(upperBound)
Generate a random number between `0` and `upperBound`

**Returns**:

  * **{Number}** between `0` and `upperBound` using a uniform distribution.

**Example**:

```javascript
var n = sodium.randombytes_uniform(100);   
console.log(n);		// number between 0 and 100
```

# Hash Functions

## crypto_shorthash(buffer, secretKey)

A lot of applications and programming language implementations have been recently found to be vulnerable to denial-of-service attacks when a hashfunction with weak security guarantees, like Murmurhash 3, was used to construct a hash table.
In order to address this, Sodium provides the "shorthash" function, currently implemented using SipHash-2-4. This very fast hash function outputs short, but unpredictable (without knowing the secret key) values suitable for picking a list in a hash table for a given key.

**Parameters**:

  * **{Buffer}** `buffer` with the data you want to hash
  * **{Buffer}** `secretKey` the secret data used as key for the hash. `secretKey` **must** be `crypto_shorthash_KEYBYTES` in length.
 
**Returns**:

  * **{Buffer}** hashed message. Length of hash is always `sodium.crypto_shorthash_BYTES`

**Constants**:

  * `crypto_shorthash_BYTES` length of the hash
  * `crypto_shorthash_KEYBYTES` length of secret key
  * `crypto_shorthash_PRIMITIVE` name of hash function used

**Example**:

```javascript
var message = new Buffer("Message to hash", "utf-8");
var key = new Buffer(sodium.crypto_shorthash_KEYBYTES);

// generate a random key
sodium.crypto_randombytes_buf(key);

// calculate the hash
var hash = sodium.crypto_shorthash(message, key);
console.log(hash);
```

## crypto_hash(buffer)
Calculate a hash of a data buffer. You can check which of the supported hash functions is used by checking `crypto_hash_PRIMITIVE`. Currently the implementation of SHA-512 is used.

The `crypto_hash` function is designed to be usable as a strong component of DSA, RSA-PSS, key derivation, hash-based message-authentication codes, hash-based ciphers, and various other common applications. "Strong" means that the security of these applications, when instantiated with crypto_hash, is the same as the security of the applications against generic attacks. In particular, the crypto_hash function is designed to make finding collisions difficult.

**Parameters**:

  * **{Buffer}** `buffer` with the data you want to hash
 
**Returns**:

  * **{Buffer}** hashed message. Length of hash is always `sodium.crypto_hash_BYTES`

**Constants**:

  * `crypto_hash_BYTES` length of the hash
  * `crypto_hash_PRIMITIVE` name of hash function used

**Example**:

```javascript
var message = new Buffer("Message to hash", "utf-8");

// calculate the hash
var hash = sodium.crypto_hash(message, key);
console.log(hash);
```
**See Also**:
 
  * [crypto_hash_sha256](#crypto_hash_sha256buffer)
  * [crypto_hash_sha512](#crypto_hash_sha512buffer)


## crypto_hash_sha256(buffer)
Calculate a SHA256 of a data buffer. 

**Parameters**:

  * **{Buffer}** `buffer` with the data you want to hash
 
**Returns**:

  * **{Buffer}** hashed message
  
**Constants**:

  * `crypto_hash_sha256_BYTES` length of the hash

**Example**:

```javascript
var message = new Buffer("Message to hash", "utf-8");

// calculate the hash
var hash = sodium.crypto_hash_sha256(message, key);
console.log(hash);
```

**See Also**:
 
  * [crypto_hash](#crypto_hashbuffer)
  * [crypto_hash_sha512](#crypto_hash_sha512buffer)


## crypto_hash_sha512(buffer)
Calculate a SHA256 of a data buffer. 

**Parameters**:

  * **{Buffer}** `buffer` with the data you want to hash
 
**Returns**:

  * **{Buffer}** hashed message
  
**Constants**:

  * `crypto_hash_sha512_BYTES` length of the hash


**Example**:

```javascript
var message = new Buffer("Message to hash", "utf-8");

// calculate the hash
var hash = sodium.crypto_hash_sha512(message, key);
console.log(hash);
```

**See Also**:
 
  * [crypto_hash](#crypto_hashbuffer)
  * [crypto_hash_sha256](#crypto_hash_sha512buffer)


# Authentication Functions


## crypto_auth(message, secretKey)
The `crypto_auth` function authenticates a `message` using a `secretKey`. The function returns an authenticator `token`. The authenticator length is always `crypto_auth_BYTES`.

### Security model

The `crypto_auth` function, viewed as a function of the message for a uniform random key, is designed to meet the standard notion of unforgeability. This means that an attacker cannot find authenticators for any messages not authenticated by the sender, even if the attacker has adaptively influenced the messages authenticated by the sender. For a formal definition see, e.g., Section 2.4 of Bellare, Kilian, and Rogaway, "The security of the cipher block chaining message authentication code," [Journal of Computer and System Sciences 61 (2000), 362–399;](http://www-cse.ucsd.edu/~mihir/papers/cbc.html).

NaCl/Libsodium does not make any promises regarding "strong" unforgeability; perhaps one valid authenticator can be converted into another valid authenticator for the same message. NaCl also does not make any promises regarding "truncated unforgeability."

**Parameters**:

  * **{Buffer}** `message` to authenticate
  * **{Buffer}** `secretKey` secret key used to authenticate the message and generate the authentication `token`. **Must** be `crypto_auth_KEYBYTES` in length

**Returns**

  * **{Buffer}** message authentication `token`

**Constants**:

  * `crypto_auth_KEYBYTES` length of secret key buffer
  * `crypto_auth_BYTES` length of authentication token buffer
  
**Example**:

```javascript
var message = new Buffer(200);
var key = new Buffer(sodium.crypto_auth_KEYBYTES);

// fill message with random data
sodium.crypto_randombytes(message);

// generate a random secret key
sodium.crypto_randombytes(key);

var token = sodium.crypto_auth(message, key);
var r = sodium.crypto_auth_verify(token, message, key);
if( r != 0) {
	console.log("message authentication failed");
}
else {
	console.log("message authenticated");
}
```

**See Also**:

  * [crypto_auth_verify](#crypto_auth_verifytoken-message-key)
  

## crypto_auth_verify(token, message, secretKey)
The `crypto_auth_verify` function verifies if the `token` is a correct authenticator generated by `crypto_auth` `message` and `secretKey`.

**Parameters**:

  * **{Buffer}** `token` message authenticator. **Must** be `crypto_auth_BYTES` in length
  * **{Buffer}** `message` to authenticate
  * **{Buffer}** `secretKey` same secret key used in the `crypto_auth` call. **Must** be `crypto_auth_KEYBYTES` in length

**Returns**

  * `0` if `token` is a correct authenticator of `message` under `secretKey`
  * `-1` otherwise

**Constants**:

  * `crypto_auth_KEYBYTES` length of secret key buffer
  * `crypto_auth_BYTES` length of authentication token buffer
  
**Example**:

```javascript
var message = new Buffer(200);
var key = new Buffer(sodium.crypto_auth_KEYBYTES);

// fill message with random data
sodium.crypto_randombytes(message);

// generate a random secret key
sodium.crypto_randombytes(key);

var token = sodium.crypto_auth(message, key);
var r = sodium.crypto_auth_verify(token, message, key);
if( r != 0) {
	console.log("message authentication failed");
}
else {
	console.log("message authenticated");
}
```

**See Also**:

  * [crypto_auth](#crypto_authmessage-key)
  

