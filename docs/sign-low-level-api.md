# Sign Low Level API

## Detailed Description

Use Sign digitally sign messages.

The crypto_sign function is designed to meet the standard notion of unforgeability for a public-key signature scheme under chosen-message attacks.

# Usage

    var sodium = require('sodium').api;

    // example of calling crypto_sign_keypair
    var keys = sodium.crypto_sign_keypair();

    // example of accessing a constant
    var sizePublicKey = sodium.crypto_sign_PUBLICKEYBYTES;


## Constants

  * `crypto_sign_BYTES` length of resulting signature.
  * `crypto_sign_PUBLICKEYBYTES` length of verification key.
  * `crypto_sign_SECRETKEYBYTES` length of signing key.

## Functions

### crypto_sign_keypair ( )

Generates a random signing key pair with a secret key and corresponding public key. Returns an object as with two buffers as follows:

    { secretKey: <secret, or signer's key buffer>,
      publicKey: <public, or validation, key buffer> }
     
### crypto_sign(message, secretKey)

Signs `message` using the signer's signing secret key

Parameters:

  * `message` - buffer with message to sign
  * `secretKey` - buffer with signer's secret key
  
Returns:

  * buffer with signed message
  * `undefined` in case or error

        
### crypto_sign_open(signedMsg, publicKey)

Verifies the signed message sig using the signer's verification key.

Parameters:

  * `signedMsg` - buffer with signed message
  * `publicKey` - buffer with signer's public key
  
Returns:

  * buffer with message
  * `undefined` if signature cannot be verified

## Credits

This document is based on [documentation](http://mob5.host.cs.st-andrews.ac.uk/html) written by Jan de Muijnck-Hughes.

