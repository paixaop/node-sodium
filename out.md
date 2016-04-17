## Authenticated Encryption with Additional Data


Encrypts a message with a key and a nonce to keep it confidential Computes
an authentication tag. This tag is used to make sure that the message, as
well as optional, non-confidential (non-encrypted) data, haven't been
tampered with.

A typical use case for additional data is to store protocol-specific metadata
about the message, such as its length and encoding.

### Crypto AEAD AES 256 GCM


The current implementation of this construction is hardware-accelerated and
requires the Intel SSSE3 extensions, as well as the aesni and pclmul
instructions.

Intel Westmere processors (introduced in 2010) and newer meet the requirements.

There are no plans to support non hardware-accelerated implementations of
AES-GCM. If portability is a concern, use ChaCha20-Poly1305 instead.

### Low Level API



### crypto_aead_aes256gcm_is_available


Check hardware support for AES 256 GCM

**Returns**:

* `true` <span class='dash'>&mdash;</span> if hardware supports AES 256 GCM

**Sample**:

```js
if( sodium.crypto_aead_aes256gcm_is_available() ) {
  // You can use the crypto_aead_aes256gcm_*()
}
else {
  // Use crypto_aead_chacha20poly1305_*()
}
```

### crypto_aead_aes256gcm_beforenm

Precompute AES key expansion.

Applications that encrypt several messages using the same key can gain a
little speed by expanding the AES key only once, via the precalculation interface
Initializes a context ctx by expanding the key k and always returns 0.

```js
var ctx = sodium.crypto_aead_aes256gcm_beforenm(key);
```

* `key` *(Buffer)* <span class='dash'>&mdash;</span>  AES 256 GCM Key buffer with crypto_aead_aes256gcm_KEYBYTES in length

**Sample**:

```js
// Generate a random key
var key = new Buffer(crypto_aead_aes256gcm_KEYBYTES);
sodium.randombytes_buf(key);
var state = sodium.crypto_aead_aes256gcm_beforenm(key);
```

### crypto_aead_aes256gcm_encrypt_afternm

Encrypt data

```js
 var c = sodium.crypto_aead_aes256gcm_encrypt_afternm(
           message,
           additionalData,
           nonce,
           ctx);
```

* `message` *(Buffer)* <span class='dash'>&mdash;</span> plain text buffer
* `additionalData` *(Buffer)* <span class='dash'>&mdash;</span> non-confidential data to add to the cipher text. Can be `null`
* `nonce` *(Buffer)* <span class='dash'>&mdash;</span> a nonce with `sodium.crypto_aead_aes256gcm_NPUBBYTES` in length
* `ctx` *(Buffer)* <span class='dash'>&mdash;</span> state computed by `crypto_aead_aes256gcm_beforenm()`

**Returns**:

* `cipherText` *(Buffer)* <span class='dash'>&mdash;</span> The encrypted message, as well as a tag authenticating
  both the confidential message `message` and non-confidential data `additionalData`

**Sample**:

```js
// Generate a random key
var key = new Buffer(crypto_aead_aes256gcm_KEYBYTES);
sodium.randombytes_buf(key);

// Generate random nonce
var nonce = new Buffer(crypto_aead_aes256gcm_KEYBYTES);
sodium.randombytes_buf(nonce);

// Precompute and generate the state
var state = sodium.crypto_aead_aes256gcm_beforenm(key);

var message = new Buffer("this is a plain text message");
var additionalData = new Buffer("metadata");
var cipherText = sodium.crypto_aead_aes256gcm_encrypt_afternm(
   message, additionalData, nonce, state);
```

Register function calls in node binding
