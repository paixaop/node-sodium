# SecretBox Low Level API

## Usage

    var sodium = require('sodium').api;

    // encrypt
    var cipherText = sodium.crypto_secretbox(message, nonce, key);

    // decrypt
    var plainText = sodium.crypto_secretbox_open(cipherText, nonce, key);

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