/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var should = require('should');
var crypto = require('crypto');
var sodium = require('../build/Release/sodium');


describe('Sign', function() {
    it('crypto_sign_keypair should return a pair of keys', function(done) {
        var keys = sodium.crypto_sign_keypair();
        keys.should.have.type('object');
        keys.should.have.properties('publicKey', 'secretKey');
        keys.publicKey.should.have.length(sodium.crypto_sign_PUBLICKEYBYTES);
        keys.secretKey.should.have.length(sodium.crypto_sign_SECRETKEYBYTES);
        done();
    });

    it('a signed message should verify correctly', function(done) {
        var keys = sodium.crypto_sign_keypair();
        var message = new Buffer("Libsodium is cool", 'utf8');
        var signedMsg = sodium.crypto_sign(message, keys.secretKey);

        var message2 = sodium.crypto_sign_open(signedMsg, keys.publicKey);
        message2.toString('utf8').should.eql(message.toString('utf8'));
        done();
    });

    it('should throw with less than 2 arguments', function(done) {
        var keys = sodium.crypto_sign_keypair();
        var message = new Buffer("Libsodium is cool", 'utf8');

        (function() {
            var signedMsg = sodium.crypto_sign(message);
        }).should.throw();
        done();
    });

    it('should throw with no params', function(done) {
        var keys = sodium.crypto_sign_keypair();
        var message = new Buffer("Libsodium is cool", 'utf8');

        (function() {
            var signedMsg = sodium.crypto_sign();
        }).should.throw();
        done();
    });

    it('should throw with a small key', function(done) {
        var message = new Buffer("Libsodium is cool", 'utf8');

        (function() {
            var signedMsg = sodium.crypto_sign(message, new Buffer(12));
        }).should.throw();
        done();
    });

    it('should test bad arg 1', function(done) {
        var message = new Buffer("Libsodium is cool", 'utf8');
        var keys = sodium.crypto_sign_keypair();
        (function() {
            var signedMsg = sodium.crypto_sign(1, keys.secretKey);
        }).should.throw();
        done();
    });

    it('should test bad arg 2', function(done) {
        var message = new Buffer("Libsodium is cool", 'utf8');
        var keys = sodium.crypto_sign_keypair();
        (function() {
            var signedMsg = sodium.crypto_sign(message, 1);
        }).should.throw();
        done();
    });

    it('should test bad arg 2', function(done) {
        var message = new Buffer("Libsodium is cool", 'utf8');
        var keys = sodium.crypto_sign_keypair();
        (function() {
            var signedMsg = sodium.crypto_sign(message, "123");
        }).should.throw();
        done();
    });
});
