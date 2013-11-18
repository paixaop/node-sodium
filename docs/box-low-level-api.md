# Box Low Level API

## Detailed Description

Definitions and functions to perform Authenticated Encryption.

Authentication encryption provides guarantees towards the:

  * confidentiality
  * integrity
  * authenticity of data.

Alongside the standard interface there also exists a pre-computation interface. In the event that applications are required to send several messages to the same receiver, speed can be gained by splitting the operation into two steps: before and after. Similarly applications that receive several messages from the same sender can gain speed through the use of the: `before`, and `open_after` functions.

# Usage

    var sodium = require('sodium').api;

    // example of calling crypto_box_keypair
    var keys = sodium.crypto_box_keypair();

    // example of accessing a constant
    var sizePublicKey = sodium.crypto_box_PUBLICKEYBYTES;

## Constants

  * `crypto_box_PUBLICKEYBYTES` Size of Public Key
  * `crypto_box_SECRETKEYBYTES` Size of Secret Key
  * `crypto_box_BEFORENMBYTES`  Size of pre-computed ciphertext
  * `crypto_box_NONCEBYTES`     Size of Nonce
  * `crypto_box_ZEROBYTES`      No. of leading 0 bytes in the message
  * `crypto_box_BOXZEROBYTES`   No. of leading 0 bytes in the cipher-text

## Functions

### crypto_box_keypair ( )

Generates a random secret key and a corresponding public key.

Returns:

  * Object

        { secretKey: <secret key buffer>,
          publicKey: <public key buffer> }

  * `undefined` in case or error

### crypto_box (message, nonce, pk, sk)

Encrypts a message given the senders secret key, and receivers public key. 

Parameters:

  * `message` - buffer with message to encrypt
  * `nonce` - buffer with crypto box nonce
  * `pk` - buffer with recipient's public key
  * `sk` - buffer with sender's secret key

Returns:

  * buffer with encrypted message
  * `undefined` in case or error


### crypto_box_open (ctxt, nonce, pk, sk)

Decrypts a ciphertext ctxt given the receivers private key, and senders public key and the same nonce that was used when calling `crypto_box`. 

Parameters:

  * `ctxt` - buffer with cipher text
  * `nonce` - buffer with crypto box nonce
  * `pk` - buffer with sender's public key
  * `sk` - buffer with recipient's secret key
  
Returns 

  * plain text buffer
  * `undefined` in case or error  

### crypto_box_beforenm (pk, sk)
Partially performs the computation required for both encryption and decryption of data. 

Parameters:

  * `pk` - buffer with sender's public key
  * `sk` - buffer with recipient's secret key
  
Returns:

  * `k` the pre-computation result to be used in the `afternm` function calls
  * `undefined` in case of error.

### crypto_box_afternm (msg, nonce, k)

Encrypts a given a message m, using partial computed data. 

Parameters:

  * `message` - buffer with message to encrypt
  * `nonce` - buffer with crypto box nonce
  * `k` - buffer calculated by the [`crypto_box_beforenm`](#crypto_box_beforenm-pk-sk) function call

Returns 

  * ciphered text buffer
  * `undefined` in case or error 

### crypto_box_open_afternm (ctxt, nonce, k)

Decrypts a ciphertext ctxt given the receivers private key, and senders public key. 

Parameters:

  * `ctxt` - buffer with cipher text
  * `nonce` - buffer with crypto box nonce
  * `k` - buffer calculated by the  [`crypto_box_beforenm`](#crypto_box_beforenm-pk-sk) function call
 
Returns 

  * plain text buffer
  * `undefined` in case or error 

## Credits
This document is based on [documentation](http://mob5.host.cs.st-andrews.ac.uk/html) written by Jan de Muijnck-Hughes.
