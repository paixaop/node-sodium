var assert = require('assert');
var sodium = require('../build/Release/sodium');

var rs = Buffer.from([
    0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91, 0x6d, 0x11, 0xc2,
    0xcb, 0x21, 0x4d, 0x3c, 0x25, 0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23,
    0x4e, 0x65, 0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80
]);


describe("libsodium_onetimeauth7", function () {
    it('crypto_onetimeauth_verify', function() {
        for (var clen = 0; clen < 1000; ++clen) {
            var key = sodium.crypto_onetimeauth_keygen();
            var c = Buffer.alloc(clen);
            sodium.randombytes_buf(c);
            var a = sodium.crypto_onetimeauth(c, key);

            var result = sodium.crypto_onetimeauth_verify(a, c, key);
            assert(result);

            if (clen > 0) {
                var i = Math.floor(Math.random() * Math.floor(clen));
                c[i] += 1;
                assert(!sodium.crypto_onetimeauth_verify(a, c, key));
                    
                i = Math.floor(Math.random() * Math.floor(a.length));
                a[i] += 1;
                assert(!sodium.crypto_onetimeauth_verify(a, c, key));
            }
        }
    });
});

