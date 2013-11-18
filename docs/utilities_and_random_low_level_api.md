# Utilities and Random Low Level API

## Usage

    var sodium = require('sodium').api;

    // example of calling crypto_box_keypair
    var version = sodium.sodium_version_string();

    // example of accessing a constant
    var num = sodium.randombytes_random();

## Version Functions

### sodium_version_string ( )

Returns:

  * String with full lib sodium version. Example `1.0.2`
  
### sodium_library_version_minor ( )

Returns:

  * Number of minor lib sodium version 
  
### sodium_library_version_major ( )

Returns:

  * Number of major lib sodium version
  
## Utilities

### memzero (buffer)

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
Return a random 32-bit unsigned value. 

### randombytes_uniform (upperBound)
Return a value between `0` and `upperBound` using a uniform distribution.
