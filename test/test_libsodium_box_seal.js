var assert = require('assert');
var sodium = require('../build/Release/sodium');


describe("libsodium_box_seal", function () {
    it('should seal and open message', function() {
        var keys = sodium.crypto_box_keypair();

        var m_len = sodium.randombytes_uniform(1000);
        m     = Buffer.allocUnsafe(m_len);
        sodium.randombytes_buf(m);

        var c = sodium.crypto_box_seal(m, keys.publicKey);
        assert( c !== null );
        
        var m2 = sodium.crypto_box_seal_open(c, keys.publicKey, keys.secretKey);
        assert( m2 !== null);
        assert(m.equals(m2));
        
        assert.throws(function() {
            m2 = sodium.crypto_box_seal_open(null, keys.publicKey, keys.secretKey);
        });

        m2 = sodium.crypto_box_seal_open(c, keys.secretKey, keys.publicKey);
        assert(m2 == null);
        
        var c2 = c.slice(0, c.length - 1);
        m2 = sodium.crypto_box_seal_open(c2, keys.publicKey, keys.secretKey);
        assert(m2 == null);

        assert(sodium.crypto_box_SEALBYTES > 0);
    });
});

