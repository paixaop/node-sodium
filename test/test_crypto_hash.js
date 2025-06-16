/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var assert = require('assert');
var sodium = require('../build/Release/sodium');
var crypto = require('crypto');


describe('Hash', function() {
    const testVectors = [
        {
            description: 'empty',
            input: Buffer.alloc(0),
            chunkedInputs: [
                [Buffer.alloc(0), Buffer.alloc(0)],
                [Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0)],
            ],
            expectedOutput: {
                sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                sha512: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
            },
        },
        {
            description: 'ASCII "abc"',
            input: Buffer.from('abc', 'ascii'),
            chunkedInputs: [
                [Buffer.from('', 'ascii'), Buffer.from('abc', 'ascii')],
                [Buffer.from('abc', 'ascii'), Buffer.from('', 'ascii')],
                [Buffer.from('a', 'ascii'), Buffer.from('bc', 'ascii')],
            ],
            expectedOutput: {
                sha256: 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
                sha512: 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
            },
        },
        {
            description: 'ASCII "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"',
            input: Buffer.from('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu', 'ascii'),
            chunkedInputs: [],
            expectedOutput: {
                sha256: 'cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1',
                sha512: '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909',
            },
        },
        {
            description: 'byte 0x01 repeated 1 million times',
            input: Buffer.alloc(1000000, 0x01),
            chunkedInputs: [
                [Buffer.alloc(999999, 0x01), Buffer.alloc(1, 0x01)],
                [Buffer.alloc(100000, 0x01), Buffer.alloc(500000, 0x01), Buffer.alloc(400000, 0x01)],
            ],
            expectedOutput: {
                sha256: '1fb6a051d8996888485d47fea0007a88e1e78ea273fa5fb60e1ab00608dbb764',
                sha512: '1a32b7c186fac5b7492c2fc74a081382b05c07e6adb30e583a25f16053e55fdbba0dbce00449c70554a12be6f8a57244bb4115f6b21a705e27d94c862b3be86a',
            },
        },
    ];

    for (const testVector of testVectors) {
        it('crypto_hash_sha256 should handle input ' + testVector.description, function(done) {
            const expectedOutput = testVector.expectedOutput.sha256;

            // Sanity check to make sure Node crypto matches our expected output.
            const nodeCryptoOutput = crypto.createHash('sha256').update(testVector.input).digest('hex');
            assert.equal(nodeCryptoOutput, expectedOutput);

            const oneShotOutput = sodium.crypto_hash_sha256(testVector.input).toString('hex');
            assert.equal(oneShotOutput, expectedOutput);

            for (const chunkedInput of testVector.chunkedInputs) {
                const state = sodium.crypto_hash_sha256_init();
                for (const chunk of chunkedInput) {
                    sodium.crypto_hash_sha256_update(state, chunk);
                }
                const multiShotOutput = sodium.crypto_hash_sha256_final(state).toString('hex');
                assert.equal(multiShotOutput, expectedOutput);
            }
            done();
        });

        it('crypto_hash_sha512 should handle input ' + testVector.description, function(done) {
            const expectedOutput = testVector.expectedOutput.sha512;

            // Sanity check to make sure Node crypto matches our expected output.
            const nodeCryptoOutput = crypto.createHash('sha512').update(testVector.input).digest('hex');
            assert.equal(nodeCryptoOutput, expectedOutput);

            const oneShotOutput = sodium.crypto_hash_sha512(testVector.input).toString('hex');
            assert.equal(oneShotOutput, expectedOutput);

            const aliasOneShotOutput = sodium.crypto_hash(testVector.input).toString('hex');
            assert.equal(aliasOneShotOutput, expectedOutput);

            for (const chunkedInput of testVector.chunkedInputs) {
                const state = sodium.crypto_hash_sha512_init();
                for (const chunk of chunkedInput) {
                    sodium.crypto_hash_sha512_update(state, chunk);
                }
                const multiShotOutput = sodium.crypto_hash_sha512_final(state).toString('hex');
                assert.equal(multiShotOutput, expectedOutput);
            }
            done();
        });
    }
});


describe('Hash', function() {
    it('should return sha hash', function(done) {
        var buf = Buffer.alloc(100, 1);
        var r = sodium.crypto_hash(buf);
        var hashString = r.toString('hex');
        assert.equal(hashString, "ceacfdb0944ac37da84556adaac97bbc9a0190ae8ca091576b91ca70e134d1067da2dd5cc311ef147b51adcfbfc2d4086560e7af1f580db8bdc961d5d7a1f127");
        assert.equal(hashString, crypto.createHash('sha512').update(buf).digest('hex'));
        done();
    });

    it('should calculate same hash as the crypto module', function(done) {
        var buf = Buffer.alloc(100, 1);
        var r = sodium.crypto_hash(buf);
        var hashString = r.toString('hex');
        assert.equal(hashString, crypto.createHash('sha512').update(buf).digest('hex'));
        done();
    });

    it('should return sha512', function(done) {
        var buf = Buffer.alloc(100, 1);
        var r = sodium.crypto_hash_sha512(buf);
        var hashString = r.toString('hex');
        assert.equal(hashString, "ceacfdb0944ac37da84556adaac97bbc9a0190ae8ca091576b91ca70e134d1067da2dd5cc311ef147b51adcfbfc2d4086560e7af1f580db8bdc961d5d7a1f127");
        done();
    });

    it('should calculate same hash as the crypto module', function(done) {
        var buf = Buffer.alloc(100, 1);
        var r = sodium.crypto_hash_sha256(buf);
        var hashString = r.toString('hex');
        assert.equal(hashString, crypto.createHash('sha256').update(buf).digest('hex'));
        done();
    });
});

describe('crypto_hash_sha512 verify parameters', function() {
    it('bad param 1', function(done) {
         assert.throws(function() {
            var r = sodium.crypto_hash_sha512("buf");
        });

         assert.throws(function() {
            var r = sodium.crypto_hash_sha512(1);
        });
        done();
    });
});

describe('crypto_hash_sha verify parameters', function() {
    it('bad param 1', function(done) {
         assert.throws(function() {
            var r = sodium.crypto_hash_sha("buf");
        });

         assert.throws(function() {
            var r = sodium.crypto_hash_sha(1);
        });
        done();
    });
});

describe('crypto_hash_sha256 verify parameters', function() {
    it('bad param 1', function(done) {
         assert.throws(function() {
            var r = sodium.crypto_hash_sha256("buf");
        });

         assert.throws(function() {
            var r = sodium.crypto_hash_sha256(1);
        });
        done();
    });
});

describe('issue #141', function() {
    it('should not core dump', function() {
        'use strict';
        const state = sodium.crypto_hash_sha512_init();
        assert(Buffer.isBuffer(state));
        sodium.crypto_hash_sha512_update(state, Buffer.alloc(128));
        const result = sodium.crypto_hash_sha512_final(state);
        assert(Buffer.isBuffer(result));
    })
})