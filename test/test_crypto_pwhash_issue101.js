const assert = require('assert');
const sodium = require('../build/Release/sodium');

describe('pwhash_str', function() {
    it('the generated hash should be a string containing no nulls', function(done) {
        var password = Buffer.from('this is a test password','utf8');
    
        var out = sodium.crypto_pwhash_str(
                    password,
                    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
                    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE);
	assert.equal(typeof out, 'string');
	assert.equal(out.indexOf('\0'), -1 );
        
        done();
    });
});
    
describe('pwhash_argon2i_str', function() {
    it('the generated hash should be a string containing no nulls', function(done) {
        var password = Buffer.from('this is a test password','utf8');
        var out = sodium.crypto_pwhash_argon2i_str(
                    password,
                    sodium.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE,
                    sodium.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE);
	assert.equal(typeof out, 'string');
	assert.equal(out.indexOf('\0'), -1 );
        done();
    });
});

describe('PWHash scryptsalsa208sha256', function() {
    it('the generated hash should be a string containing no nulls', function(done) {
        var password = Buffer.from('this is a test password','utf8');
        var out = sodium.crypto_pwhash_scryptsalsa208sha256_str(
                    password,
                    sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,
                    sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
	assert.equal(typeof out, 'string');
	assert.equal(out.indexOf('\0'), -1 );
        done();
    });
});
