/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var assert = require('assert');
var crypto = require('crypto');
var sodium = require('../build/Release/sodium');

var key = new Buffer(sodium.crypto_auth_KEYBYTES).fill('Jefe').fill(0, 4, 32);;
var c = Buffer.from('what do ya want for nothing?');

var key2 = Buffer.from('Another one got caught today, it\'s all over the papers. "Teenager Arrested in Computer Crime Scandal", "Hacker Arrested after Bank Tampering"... Damn kids. They\'re all alike.');

testAlgorithm('hmacsha256');
testAlgorithm('hmacsha512');
testAlgorithm('hmacsha512256');

function testAlgorithm(algo) {
    describe('LibSodium Auth', function() {
        it('crypto_auth_' + algo + '_* = crypto_auth_' + algo, function(done) {
            // Split the message in half
            var c1 = c.slice(0, c.length / 2);
            var c2 = c.slice(c.length / 2, c.length);

            var s1 = sodium['crypto_auth_' + algo + '_init'](key);
            var s2 = sodium['crypto_auth_' + algo + '_update'](s1, c1);
            var s3 = sodium['crypto_auth_' + algo + '_update'](s2, c2);
            var a1 = sodium['crypto_auth_' + algo + '_final'](s3);

            var a2 = sodium['crypto_auth_' + algo](c, key);

            // Assert that the states changed with each update
            assert.notDeepEqual(s1, s2);
            assert.notDeepEqual(s2, s3);
            assert.notDeepEqual(s1, s3);

            // Assert that it matches what we expected
            assert.deepEqual(a1, a2);

            // Is it the right token length
            assert.equal(a1.length, sodium['crypto_auth_' + algo + '_BYTES']);
            assert.equal(a2.length, sodium['crypto_auth_' + algo + '_BYTES']);
            done();
        });

        it('crypto_auth_' + algo +' must verify auth token', function(done) {
            // Split the message in half
            var c1 = c.slice(0, c.length / 2);
            var c2 = c.slice(c.length / 2, c.length);

            var s1 = sodium['crypto_auth_' + algo + '_init'](key);
            var s2 = sodium['crypto_auth_' + algo + '_update'](s1, c1);
            var s3 = sodium['crypto_auth_' + algo + '_update'](s2, c2);
            var a1 = sodium['crypto_auth_' + algo + '_final'](s3);

            var a2 = sodium['crypto_auth_' + algo](c, key);

            // Assert that the states changed with each update
            assert.notDeepEqual(s1, s2);
            assert.notDeepEqual(s2, s3);
            assert.notDeepEqual(s1, s3);

            // Assert that it matches what we expected
            assert.deepEqual(a1, a2);

            assert.equal(sodium['crypto_auth_' + algo + '_verify'](a1, c, key), 0);
            assert.equal(sodium['crypto_auth_' + algo + '_verify'](a2, c, key), 0);

            done();
        });

        it('crypto_auth_' + algo +' must verify auth token with big key', function(done) {
            // Split the message in half
            var c1 = c.slice(0, c.length / 2);
            var c2 = c.slice(c.length / 2, c.length);

            var s1 = sodium['crypto_auth_' + algo + '_init'](key2);
            var s2 = sodium['crypto_auth_' + algo + '_update'](s1, c1);
            var s3 = sodium['crypto_auth_' + algo + '_update'](s2, c2);
            var a1 = sodium['crypto_auth_' + algo + '_final'](s3);

            var a2 = sodium['crypto_auth_' + algo](c, key);

            // Assert that the states changed with each update
            assert.notDeepEqual(s1, s2);
            assert.notDeepEqual(s2, s3);
            assert.notDeepEqual(s1, s3);

            var hashAlgo = null;
            switch(algo) {
                case 'hmacsha256':
                    hashAlgo = 'sha256'; break;
                case 'hmacsha512':
                    hashAlgo = 'sha512'; break;
                case 'hmacsha512256':
                    hashAlgo = 'sha512'; break;
            }
            var hKey = sodium['crypto_hash_' + hashAlgo](key2);
            assert.equal(sodium['crypto_auth_' + algo + '_verify'](a1, c, hKey), 0);
            assert.equal(sodium['crypto_auth_' + algo + '_verify'](a2, c, hKey), 0);

            done();
        });
    });
}