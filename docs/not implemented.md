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
  
  * crypto_aead_chacha20poly1305_decrypt
  * crypto_aead_chacha20poly1305_decrypt_detached
  * crypto_aead_chacha20poly1305_encrypt
  * crypto_aead_chacha20poly1305_encrypt_detached
  
  * crypto_aead_chacha20poly1305_ietf_decrypt
  * crypto_aead_chacha20poly1305_ietf_decrypt_detached
  * crypto_aead_chacha20poly1305_ietf_encrypt
  * crypto_aead_chacha20poly1305_ietf_encrypt_detached
  
  * crypto_box_detached_afternm
  * crypto_box_easy_afternm
  * crypto_box_open_easy_afternm
  
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