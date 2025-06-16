var assert = require('assert');
var sodium = require('../build/Release/sodium');


describe("libsodium_aead_xchacha20poly1305_ietf", function () {
    it('encrypt/decript should match messages and such fro ietf', function() {
        firstKey = Buffer.from([
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f
        ]);
        assert.equal(firstKey.length, sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

        var m = Buffer.from(
            "Ladies and Gentlemen of the class of '99: If I could offer you " +
            "only one tip for the future, sunscreen would be it.");

        var clen = m.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES;

        var nonce = Buffer.from([
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 
            0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]);

        assert.equal(nonce.length, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

        var ad = Buffer.from([
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 
            0xc4, 0xc5, 0xc6, 0xc7 ]);

        var cipherTextSodium = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
            m, ad, nonce, firstKey);

        assert.equal(cipherTextSodium.length, clen);

        var c = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            m, ad, nonce, firstKey);

        assert.equal(c.mac.length, sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES);
        
        //Get just the cipher text and compare
        var temp = cipherTextSodium.slice(0, m.length);
        assert(c.cipherText.equals(temp));

        var plainTextSodium = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            cipherTextSodium, ad, nonce, firstKey);

        assert(m.equals(plainTextSodium));

        var plainText = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            c.cipherText, c.mac, ad, nonce, firstKey);
        
        assert(m.equals(plainText));

        for(var i = 0; i< clen; i++) {
            cipherTextSodium[i] ^= (i + 1);
            var plainText = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                cipherTextSodium, null, nonce, firstKey);

            assert(plainText === null);
            cipherTextSodium[i] ^= (i + 1);
        }
    });
});
