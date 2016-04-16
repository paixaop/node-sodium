var should = require('should');
var sodium = require('../build/Release/sodium');
var assert = require('assert');

describe("AEAD", function () {
    it("aes256gcm should encrypt and decrypt to the same string", function (done) {
        var message = new Buffer("This is a plain text message");
        var additionalData = new Buffer("this is metadata");
        
        var nonce = new Buffer(sodium.crypto_aead_aes256gcm_NPUBBYTES);
        sodium.randombytes_buf(nonce);
        
        var key = new Buffer(sodium.crypto_aead_aes256gcm_KEYBYTES);
        sodium.randombytes_buf(key);
        
        // If CPU does not support AES256gcm don't test
        if( !sodium.crypto_aead_aes256gcm_is_available() ) {
            console.log('AES 256 gcm not supported by CPU');
            done();
        }
        
        // Encrypt data
        var cipherText = sodium.crypto_aead_aes256gcm_encrypt(message, additionalData, nonce, key);
        
        // Decrypt Data
        var plainText = sodium.crypto_aead_aes256gcm_decrypt(cipherText, additionalData, nonce, key);
        
        // Test equality
        assert(sodium.compare(plainText, message)==0);
        done();
    });
    
    it("aes256gcm should encrypt and decrypt to the same string with null additional data", function (done) {
        var message = new Buffer("This is a plain text message");
        var additionalData = new Buffer("this is metadata");
        
        var nonce = new Buffer(sodium.crypto_aead_aes256gcm_NPUBBYTES);
        sodium.randombytes_buf(nonce);
        
        var key = new Buffer(sodium.crypto_aead_aes256gcm_KEYBYTES);
        sodium.randombytes_buf(key);
        
        // If CPU does not support AES256gcm don't test
        if( !sodium.crypto_aead_aes256gcm_is_available() ) {
            console.log('AES 256 gcm not supported by CPU');
            done();
        }
        
        // Encrypt data
        var cipherText = sodium.crypto_aead_aes256gcm_encrypt(message, null, nonce, key);
        
        // Decrypt Data
        var plainText = sodium.crypto_aead_aes256gcm_decrypt(cipherText, null, nonce, key);
        
        // Test equality
        assert(sodium.compare(plainText, message)==0);
        done();
    });
    
    it("chacha20poly1305 should encrypt and decrypt to the same string", function (done) {
        var message = new Buffer("This is a plain text message");
        var additionalData = new Buffer("this is metadata");
        
        var nonce = new Buffer(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
        sodium.randombytes_buf(nonce);
        
        var key = new Buffer(sodium.crypto_aead_chacha20poly1305_KEYBYTES);
        sodium.randombytes_buf(key);
        
        // Encrypt data
        var cipherText = sodium.crypto_aead_chacha20poly1305_encrypt(message, additionalData, nonce, key);
        
        // Decrypt Data
        var plainText = sodium.crypto_aead_chacha20poly1305_decrypt(cipherText, additionalData, nonce, key);
        
        // Test equality
        assert(sodium.compare(plainText, message)==0);
        done();
    });
    
    it("chacha20poly1305 should encrypt and decrypt to the same string with null additional data", function (done) {
        var message = new Buffer("This is a plain text message");
        
        var nonce = new Buffer(sodium.crypto_aead_chacha20poly1305_NPUBBYTES);
        sodium.randombytes_buf(nonce);
        
        var key = new Buffer(sodium.crypto_aead_chacha20poly1305_KEYBYTES);
        sodium.randombytes_buf(key);
        
        // Encrypt data
        var cipherText = sodium.crypto_aead_chacha20poly1305_encrypt(message, null, nonce, key);
        
        // Decrypt Data
        var plainText = sodium.crypto_aead_chacha20poly1305_decrypt(cipherText, null, nonce, key);
        
        // Test equality
        assert(sodium.compare(plainText, message)==0);
        done();
    });
    
    it("chacha20poly1305_ietf should encrypt and decrypt to the same string", function (done) {
        var message = new Buffer("This is a plain text message");
        var additionalData = new Buffer("this is metadata");
        
        var nonce = new Buffer(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
        sodium.randombytes_buf(nonce);
        
        var key = new Buffer(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        sodium.randombytes_buf(key);
        
        // Encrypt data
        var cipherText = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(message, additionalData, nonce, key);
        
        // Decrypt Data
        var plainText = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(cipherText, additionalData, nonce, key);
        
        // Test equality
        assert(sodium.compare(plainText, message)==0);
        done();
    });
    
    it("chacha20poly1305_ietf should encrypt and decrypt to the same string with null additional data", function (done) {
        var message = new Buffer("This is a plain text message");
        
        var nonce = new Buffer(sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
        sodium.randombytes_buf(nonce);
        
        var key = new Buffer(sodium.crypto_aead_chacha20poly1305_ietf_KEYBYTES);
        sodium.randombytes_buf(key);
        
        // Encrypt data
        var cipherText = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(message, null, nonce, key);
        
        // Decrypt Data
        var plainText = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(cipherText, null, nonce, key);
        
        // Test equality
        assert(sodium.compare(plainText, message)==0);
        done();
    });
});