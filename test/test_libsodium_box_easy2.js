var assert = require('assert');
var sodium = require('../build/Release/sodium');


var small_order_p = Buffer.from([
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
    0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
    0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00
]);


describe("libsodium_box_easy2", function () {
    var alice = sodium.crypto_box_keypair();
    var bob = sodium.crypto_box_keypair();
    var m2_size = m_size = 7 + sodium.randombytes_uniform(1000);
    var mlen = sodium.randombytes_uniform(m_size) + 1;
    var m = Buffer.allocUnsafe(mlen);
    sodium.randombytes_buf(m);
    var nonce = Buffer.allocUnsafe(sodium.crypto_box_NONCEBYTES);
    sodium.randombytes_buf(nonce);

    it('should encrypt/decrypt', function() {
        var c = sodium.crypto_box_easy(m, nonce, bob.publicKey, alice.secretKey);
        var p = sodium.crypto_box_open_easy(c, nonce, alice.publicKey, bob.secretKey);
        assert(p.equals(m));
    });

    it('Precalculation interface encrypt/decrypt', function() {
        var k1 = sodium.crypto_box_beforenm(small_order_p, bob.secretKey);
        assert(k1 == null);

        var k2 = sodium.crypto_box_beforenm(small_order_p, alice.secretKey);
        assert(k2 == null);

        k1 = sodium.crypto_box_beforenm(alice.publicKey, bob.secretKey);
        assert(k1 != null);

        k2 = sodium.crypto_box_beforenm(bob.publicKey, alice.secretKey);
        assert(k2 != null);

        // crypto_box_easy_afternm() with a null ciphertext should work
        var c = sodium.crypto_box_easy_afternm(null, nonce, k1);
        assert( c != null);
        
        c = sodium.crypto_box_easy_afternm(m, nonce, k1);
        var m2 = sodium.crypto_box_open_easy_afternm(c, nonce, k2);
        assert(m.equals(m2));

        var c2 = c.slice(0, sodium.crypto_box_MACBYTES - 1);
        assert.throws(function() {
            m2 = sodium.crypto_box_open_easy_afternm(c2, nonce, k2);
        });
    });

    it('Detached interface encrypt/decrypt', function() {
        var c = sodium.crypto_box_detached(m, nonce, small_order_p,  bob.secretKey);
        assert(c == null);
        
        c = sodium.crypto_box_detached(m, nonce, alice.publicKey, bob.secretKey);
        assert(c != null);

        var m2 = sodium.crypto_box_open_detached(c.cipherText, c.mac, nonce,
                                    small_order_p,  alice.secretKey);
        assert(m2 == null);

        m2 = sodium.crypto_box_open_detached(c.cipherText, c.mac, nonce,
                                     bob.publicKey,  alice.secretKey);
        
        assert(m.equals(m2));

        k1 = sodium.crypto_box_beforenm(alice.publicKey, bob.secretKey);
        assert(k1 != null);

        k2 = sodium.crypto_box_beforenm(bob.publicKey, alice.secretKey);
        assert(k2 != null);

        c = sodium.crypto_box_detached_afternm(m, nonce, k1);
        m2.fill(0);
        m2 = sodium.crypto_box_open_detached_afternm(c.cipherText, c.mac, nonce, k2);
        assert(m.equals(m2));
    });
});

