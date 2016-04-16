/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var assert = require('assert');
var sodium = require('../build/Release/sodium');
var toBuffer = require('../lib/toBuffer');

describe('PWHash scryptsalsa208sha256', function() {
    it('should verify the generated hash with same password', function(done) {
        var password = new Buffer('this is a test password','utf8');
    
        var out = sodium.crypto_pwhash_scryptsalsa208sha256_str(
                    password,
                    sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,                                            
                    sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(out, password)); 
        
        done();
    });
    
    it('should not verify the generated hash with different passwords', function(done) {
        var password = new Buffer('this is a test password','utf8');
        var badPassword = new Buffer('this is a bad password','utf8');
        
        var out = sodium.crypto_pwhash_scryptsalsa208sha256_str(
                    password,
                    sodium.crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE,                                            
                    sodium.crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE);
        
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(out, badPassword)==false); 
        
        done();
    });
    
    it('should generate pwhash using low level scrypt API', function(done) {
        var password = new Buffer("pleaseletmein",'utf8');
        var salt = new Buffer('SodiumChloride','utf8');
        
        var result = toBuffer("7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887");
        
        var N = 16384;
        var r = 8;
        var p = 1;
        var output = new Buffer(64);
        
        sodium.crypto_pwhash_scryptsalsa208sha256_ll(password, salt, N, r, p, output);
        assert(sodium.compare(result,output)==0);
        done(); 
    });
});

describe('PWHash', function() {
    it('should verify the generated hash with same password', function(done) {
        var password = new Buffer('this is a test password','utf8');
    
        var out = sodium.crypto_pwhash_str(
                    password,
                    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,                                            
                    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE);
        assert(sodium.crypto_pwhash_str_verify(out, password)); 
        
        done();
    });
    
    it('should not verify the generated hash with different passwords', function(done) {
        var password = new Buffer('this is a test password','utf8');
        var badPassword = new Buffer('this is a bad password','utf8');
        
        var out = sodium.crypto_pwhash_str(
                    password,
                    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,                                            
                    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE);
        
        assert(sodium.crypto_pwhash_str_verify(out, badPassword)==false); 
        
        done();
    });
});
    
describe('PWHash argon2i', function() {
    it('should verify the generated hash with same password', function(done) {
        var password = new Buffer('this is a test password','utf8');
    
        var out = sodium.crypto_pwhash_argon2i_str(
                    password,
                    sodium.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE,                                            
                    sodium.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE);
        assert(sodium.crypto_pwhash_argon2i_str_verify(out, password)); 
        
        done();
    });
    
    it('should not verify the generated hash with different passwords', function(done) {
        var password = new Buffer('this is a test password','utf8');
        var badPassword = new Buffer('this is a bad password','utf8');
        
        var out = sodium.crypto_pwhash_argon2i_str(
                    password,
                    sodium.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE,                                            
                    sodium.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE);
        
        assert(sodium.crypto_pwhash_argon2i_str_verify(out, badPassword)==false); 
        
        done();
    });
});
    