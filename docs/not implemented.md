This functions from Libsodium have not yet been implemented in node-sodium
If you really need them please create a pull request and I will merge it in. Thank you for supporting the effort!

  * crypto_aead_aes256gcm_decrypt
  * crypto_aead_aes256gcm_decrypt_detached
  * crypto_aead_aes256gcm_encrypt
  * crypto_aead_aes256gcm_encrypt_detached
  
  * crypto_aead_aes256gcm_beforenm
  * crypto_aead_aes256gcm_decrypt_afternm
  * crypto_aead_aes256gcm_decrypt_detached_afternm
  * crypto_aead_aes256gcm_encrypt_afternm
  * crypto_aead_aes256gcm_encrypt_detached_afternm
  * crypto_aead_aes256gcm_is_available
  
  * crypto_aead_aes256gcm_ABYTES
  * crypto_aead_aes256gcm_KEYBYTES
  * crypto_aead_aes256gcm_NPUBBYTES
  * crypto_aead_aes256gcm_NSECBYTES
  * crypto_aead_aes256gcm_STATEBYTES

  * crypto_aead_chacha20poly1305_decrypt
  * crypto_aead_chacha20poly1305_decrypt_detached
  * crypto_aead_chacha20poly1305_encrypt
  * crypto_aead_chacha20poly1305_encrypt_detached
  * crypto_aead_chacha20poly1305_ABYTES
  * crypto_aead_chacha20poly1305_KEYBYTES
  * crypto_aead_chacha20poly1305_NPUBBYTES
  * crypto_aead_chacha20poly1305_NSECBYTES
  
  * crypto_aead_chacha20poly1305_ietf_decrypt
  * crypto_aead_chacha20poly1305_ietf_decrypt_detached
  * crypto_aead_chacha20poly1305_ietf_encrypt
  * crypto_aead_chacha20poly1305_ietf_encrypt_detached
  * crypto_aead_chacha20poly1305_ietf_ABYTES
  * crypto_aead_chacha20poly1305_ietf_KEYBYTES
  * crypto_aead_chacha20poly1305_ietf_NPUBBYTES
  * crypto_aead_chacha20poly1305_ietf_NSECBYTES
  
  * crypto_box_curve25519xsalsa20poly1305
  * crypto_box_curve25519xsalsa20poly1305_afternm
  * crypto_box_curve25519xsalsa20poly1305_beforenm
  * crypto_box_curve25519xsalsa20poly1305_keypair
  * crypto_box_curve25519xsalsa20poly1305_open
  * crypto_box_curve25519xsalsa20poly1305_open_afternm
  * crypto_box_curve25519xsalsa20poly1305_seed_keypair
  
  * crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES
  * crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES
  * crypto_box_curve25519xsalsa20poly1305_MACBYTES
  * crypto_box_curve25519xsalsa20poly1305_NONCEBYTES
  * crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
  * crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES
  * crypto_box_curve25519xsalsa20poly1305_SEEDBYTES
  * crypto_box_curve25519xsalsa20poly1305_ZEROBYTES
  
  * crypto_box_detached
  * crypto_box_detached_afternm
  * crypto_box_easy_afternm
  * crypto_box_open_detached
  * crypto_box_open_easy_afternm
  * crypto_box_seal
  * crypto_box_seal_open
  * crypto_box_seed_keypair
  
  * crypto_sign_ed25519
  * crypto_sign_ed25519_open
  * crypto_sign_ed25519_detached
  * crypto_sign_ed25519_keypair
  * crypto_sign_ed25519_seed_keypair
  * crypto_sign_ed25519_sk_to_pk
  * crypto_sign_ed25519_sk_to_seed
  * crypto_sign_ed25519_verify_detached
  
  * crypto_sign_ed25519_BYTES
  * crypto_sign_ed25519_PUBLICKEYBYTES
  * crypto_sign_ed25519_SECRETKEYBYTES
  * crypto_sign_ed25519_SEEDBYTES
  
  * crypto_sign_edwards25519sha512batch
  * crypto_sign_edwards25519sha512batch_keypair
  * crypto_sign_edwards25519sha512batch_open
  
  * randombytes_implementation_name
  * randombytes_set_implementation
  * sodium_allocarray
  * sodium_free
  * sodium_malloc
  * sodium_mlock
  * sodium_mprotect_noaccess
  * sodium_mprotect_readonly
  * sodium_mprotect_readwrite
  * sodium_munlock