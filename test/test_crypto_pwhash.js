/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var assert = require('assert');
var sodium = require('../build/Release/sodium');
var crypto = require('crypto');
var toBuffer = require('../lib/toBuffer');

describe('PWHash', function() {
    it('should verify the generated hash with same password', function(done) {
         
        var out = sodium.crypto_pwhash_scryptsalsa208sha256_str(
                    new Buffer("this is a test password"),
                    sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,                                            
                    sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
        
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(out,new Buffer("this is a test password"))); 
        
        done();
    });
    
    it('should not verify the generated hash with different passwords', function(done) {
         
        var out = sodium.crypto_pwhash_scryptsalsa208sha256_str(
                    new Buffer("this is a test password"),
                    sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,                                            
                    sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
        
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(out,new Buffer("that is a test password"))==false); 
        
        done();
    });
    
    
});
    