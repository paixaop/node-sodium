var assert = require('assert');
var sodium = require('../build/Release/sodium');


describe("libsodium_box8", function () {
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

            var faults = 5;

            while (faults > 0) {
                var i = Math.floor(Math.random() * Math.floor(mlen + sodium.crypto_box_ZEROBYTES));
                if( i <= sodium.crypto_box_ZEROBYTES ) i = sodium.crypto_box_ZEROBYTES;
                c[i]++;
                var m2 = sodium.crypto_box_open(c, n, alice.publicKey, bob.secretKey);
                if( m2 === null) faults--;
                assert(m2 === null, "mlen: " + mlen + " fault: " + faults );
            }
        }
    });
});

