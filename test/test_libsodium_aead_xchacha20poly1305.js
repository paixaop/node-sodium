var assert = require('assert');
var sodium = require('../build/Release/sodium');


describe("libsodium_aead_xchacha20poly1305_ietf", function () {
    it('encrypt/decript should match messages and such', function() {
        var firstKey = Buffer.from([
                0x42, 0x90, 0xbc, 0xb1, 0x54, 0x17, 0x35, 0x31, 0xf3, 0x14, 0xaf,
                0x57, 0xf3, 0xbe, 0x3b, 0x50, 0x06, 0xda, 0x37, 0x1e, 0xce, 0x27,
                0x2a, 0xfa, 0x1b, 0x5d, 0xbd, 0xd1, 0x10, 0x0a, 0x10, 0x07]);

        assert(firstKey.length, sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
        
        var m = Buffer.from([0x86, 0xd0, 0x99, 0x74, 0x84, 0x0b, 0xde, 0xd2, 0xa5, 0xca]);

        var nonce = Buffer.from([0xcd, 0x7c, 0xf6, 0x7b, 0xe3, 0x9c, 0x79, 0x4a]);
        assert(nonce.length, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

        var ad = Buffer.from([ 0x87, 0xe2, 0x29, 0xd4, 0x50, 0x08, 0x45, 0xa0, 0x79, 0xc0 ]);
        
        var cipherTextSodium = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(m, null, nonce, firstKey);

        assert(cipherTextSodium.length, m.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES);

        var plainText = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            cipherTextSodium, null, nonce, firstKey);

        assert(plainText.equals(m));


        var c = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt_detached(m, ad, nonce, firstKey);
        
        assert(c.mac.length, sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES);
        assert(c.cipherText.length, 10);

        var m2 = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            c.cipherText, c.mac, ad, nonce, firstKey);

        assert(m, m2);

        for(var i = 0; i< m.length + sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES; i++) {
            cipherTextSodium[i] ^= (i + 1);
            var plainText = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
                cipherTextSodium, null, nonce, firstKey);

            assert(typeof plainText, undefined);
            cipherTextSodium[i] ^= (i + 1);
        }
    });

    it('keygen help should generate keys with the right size', function() {
        var key = sodium.crypto_aead_xchacha20poly1305_ietf_keygen();
        assert(key.length, sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
    });
});
