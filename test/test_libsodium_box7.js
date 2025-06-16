var assert = require('assert');
var sodium = require('../build/Release/sodium');


describe("libsodium_box7", function () {
    it('crypto_box_keypair', function() {

        var alice = sodium.crypto_box_keypair();
        var bob = sodium.crypto_box_keypair();
        var mlen_max = 1000;
        var n = Buffer.alloc(sodium.crypto_box_NONCEBYTES).fill(0);

        for (var mlen = 0; mlen + sodium.crypto_box_ZEROBYTES <= mlen_max; mlen++) {
            sodium.randombytes_buf(n);
            var rbytes = Buffer.alloc(mlen);
            sodium.randombytes_buf(rbytes);
            var m = Buffer.alloc(sodium.crypto_box_ZEROBYTES + mlen).fill(0);
            var m2 = Buffer.alloc(sodium.crypto_box_ZEROBYTES + mlen).fill(0);
            rbytes.copy(m, sodium.crypto_box_ZEROBYTES, 0, mlen);

            var c = sodium.crypto_box(m, n, bob.publicKey, alice.secretKey);
            assert(c !== null);

            var m2 = sodium.crypto_box_open(c, n, alice.publicKey,
                                bob.secretKey);
            
            assert(m.equals(m2));
        }
    });
});

