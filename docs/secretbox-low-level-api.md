# SecretBox Low Level API

## Usage

    var sodium = require('sodium').api;

    // encrypt
    var cipherText = sodium.crypto_secretbox(message, nonce, key);

    // decrypt
    var plainText = sodium.crypto_secretbox_open(cipherText, nonce, key);
    
## Constants

 * `crypto_secretbox_KEYBYTES`     Size of shared secret key
 * `crypto_secretbox_NONCEBYTES`   Size of Nonce
 * `crypto_secretbox_BOXZEROBYTES` No. of leading 0 bytes in the cipher-text
 * `crypto_secretbox_ZEROBYTES`    No. of leading 0 bytes in the message

## Functions

### crypto_secretbox (message, nonce, key)

Encrypts and authenticates a `message` using a unique nonce and a secret `key`

Parameters:

  * `message` - buffer with message to encrypt
  * `nonce` - unique number
  * `key` - buffer with shared secret key

Returns:

  * buffer with encrypted message or `undefined` in case of error

### crypto_secretbox_open (cipherText, nonce, key )

Verifies and decrypts a `cipherText` using a unique nonce and a secret `key`

Parameters:

  * `cipherText` - buffer with message to decrypt
  * `nonce` - unique number
  * `key` - buffer with shared secret key

Returns:

  * buffer with decrypted message or `undefined` in case of error