var assert = require('assert');
var sodium = require('../build/Release/sodium');


describe("libsodium_aead_chacha20poly1305", function () {
    it('encrypt/decript should match messages and such', function() {
        var firstKey = Buffer.from([
                0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
                0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
                0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07]);

        assert(firstKey.length, sodium.crypto_aead_chacha20poly1305_KEYBYTES);
        
        var m = Buffer.from([0x86, 0xd0, 0x99, 0x74, 0x84, 0x0b, 0xde, 0xd2, 0xa5, 0xca]);

        var nonce = Buffer.from([0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a]);
        assert(nonce.length, sodium.crypto_aead_chacha20poly1305_NPUBBYTES);

        var ad = Buffer.from([ 0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0 ]);
        
        var cipherTextSodium = sodium.crypto_aead_chacha20poly1305_encrypt(m, null, nonce, firstKey);

        assert(cipherTextSodium.length, m.length + sodium.crypto_aead_chacha20poly1305_ABYTES);

        var plainText = sodium.crypto_aead_chacha20poly1305_decrypt(
            cipherTextSodium, null, nonce, firstKey);

        assert(plainText.equals(m));


        var c = sodium.crypto_aead_chacha20poly1305_encrypt_detached(m, ad, nonce, firstKey);
        
        assert(c.mac.length, sodium.crypto_aead_chacha20poly1305_ABYTES);
        assert(c.cipherText.length, 10);

        var m2 = sodium.crypto_aead_chacha20poly1305_decrypt_detached(
            c.cipherText, c.mac, ad, nonce, firstKey);

        assert(m, m2);

        for(var i = 0; i< m.length + sodium.crypto_aead_chacha20poly1305_ABYTES; i++) {
            cipherTextSodium[i] ^= (i + 1);
            var plainText = sodium.crypto_aead_chacha20poly1305_decrypt(
                cipherTextSodium, null, nonce, firstKey);

            assert(typeof plainText, undefined);
            cipherTextSodium[i] ^= (i + 1);
        }
    });

    it('keygen help should generate keys with the right size', function() {
        var key = sodium.crypto_aead_chacha20poly1305_keygen();
        assert(key.length, sodium.crypto_aead_chacha20poly1305_KEYBYTES);
    });
});


describe("libsodium_aead_chacha20poly1305_ietf", function () {
    it('encrypt/decript should match messages and such fro ietf', function() {
        firstKey = Buffer.from([
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
        ]);

        var m = Buffer.from(
            "Ladies and Gentlemen of the class of '99: If I could offer you " +
            "only one tip for the future, sunscreen would be it.");

        var clen = m.length + sodium.crypto_aead_chacha20poly1305_ietf_ABYTES;

        var nonce = Buffer.from(
            [0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]);

        assert.equal(nonce.length, sodium.crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

        var ad = Buffer.from(
            [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 ]);

        var cipherTextSodium = sodium.crypto_aead_chacha20poly1305_ietf_encrypt(
            m, ad, nonce, firstKey);

        assert.equal(cipherTextSodium.length, clen);

        var c = sodium.crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            m, ad, nonce, firstKey);

        assert.equal(c.mac.length, sodium.crypto_aead_chacha20poly1305_ietf_ABYTES);
        
        //Get just the cipher text and compare
        var temp = cipherTextSodium.slice(0, m.length);
        assert(c.cipherText.equals(temp));

        var plainTextSodium = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
            cipherTextSodium, ad, nonce, firstKey);

        assert(m.equals(plainTextSodium));

        var plainText = sodium.crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            c.cipherText, c.mac, ad, nonce, firstKey);
        
        assert(m.equals(plainText));

        for(var i = 0; i< clen; i++) {
            cipherTextSodium[i] ^= (i + 1);
            var plainText = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(
                cipherTextSodium, null, nonce, firstKey);

            assert(plainText === null);
            cipherTextSodium[i] ^= (i + 1);
        }
    });
});
