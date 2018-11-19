var assert = require('assert');
var sodium = require('../build/Release/sodium');

describe("libsodium_auth5", function () {
    it('crypto_auth_keygen, verify', function() {
        for (var clen = 0; clen < 1000; ++clen) {
            var key = sodium.crypto_auth_keygen();
            var c = Buffer.allocUnsafe(clen);
            sodium.randombytes_buf(c);

            var a = sodium.crypto_auth(c, key);

            assert(sodium.crypto_auth_verify(a, c, key) == 0);

            if (clen > 0) {
                var r = Math.floor((1000 * Math.random()) % clen);
                c[ r % clen] += 1 + (1000 * Math.random() % 255);
                assert(sodium.crypto_auth_verify(a, c, key) != 0);
                
                var r2 = Math.floor((1000 * Math.random()) % a.length);
                a[r2] += 1 + (1000 * Math.random() % 255);
                assert(sodium.crypto_auth_verify(a, c, key) != 0);
            }
        }
    });
});

