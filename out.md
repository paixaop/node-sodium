## Authenticated Encryption with Additional Data


Encrypts a message with a key and a nonce to keep it confidential Computes
an authentication tag. This tag is used to make sure that the message, as
well as optional, non-confidential (non-encrypted) data, haven't been
tampered with.

A typical use case for additional data is to store protocol-specific metadata
about the message, such as its length and encoding.

### Crypto AEAD AES 256 GCM



### crypto_aead_aes256gcm_is_available()


Check hardware support for AES 256 GCM

**Returns**:

* `true` <span class='dash'>&mdash;</span> if hardware supports AES 256 GCM

### crypto_aead_aes256gcm_beforenm(key)


Applications that encrypt several messages using the same key can gain a
little speed by expanding the AES key only once, via the precalculation interface
Initializes a context ctx by expanding the key k and always returns 0.

**Libsodium Prototype**

```js
int crypto_aead_aes256gcm_beforenm(
        crypto_aead_aes256gcm_state *ctx_,
        const unsigned char *k);
```

**Parameters**:

* `key` <span class='dash'>&mdash;</span> AES 256 GCM Key buffer with crypto_aead_aes256gcm_KEYBYTES in length

 **Example**:

```js
// Generate a random key
var key = new Buffer(crypto_aead_aes256gcm_KEYBYTES);
sodium.randombytes_buf(key);
var ctx = sodium.crypto_aead_aes256gcm_beforenm(key);
```

Register function calls in node binding
