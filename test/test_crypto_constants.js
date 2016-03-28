/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var should = require('should');
var sodium = require('../build/Release/sodium');

describe('Constants', function() {
    it('should define lib constants', function(done) {
        sodium.crypto_auth_BYTES.should.have.type('number').above(0);
        sodium.crypto_auth_KEYBYTES.should.have.type('number').above(0);
        sodium.crypto_box_NONCEBYTES.should.have.type('number').above(0);
        sodium.crypto_box_BEFORENMBYTES.should.have.type('number').above(0);
        sodium.crypto_box_BOXZEROBYTES.should.have.type('number').above(0);
        sodium.crypto_box_PUBLICKEYBYTES.should.have.type('number').above(0);
        sodium.crypto_box_SECRETKEYBYTES.should.have.type('number').above(0);
        sodium.crypto_box_ZEROBYTES.should.have.type('number').above(0);
        sodium.crypto_hash_BYTES.should.have.type('number').above(0);
        sodium.crypto_onetimeauth_BYTES.should.have.type('number').above(0);
        sodium.crypto_onetimeauth_KEYBYTES.should.have.type('number').above(0);
        sodium.crypto_secretbox_BOXZEROBYTES.should.have.type('number').above(0);
        sodium.crypto_secretbox_KEYBYTES.should.have.type('number').above(0);
        sodium.crypto_secretbox_NONCEBYTES.should.have.type('number').above(0);
        sodium.crypto_secretbox_ZEROBYTES.should.have.type('number').above(0);
        sodium.crypto_sign_BYTES.should.have.type('number').above(0);
        sodium.crypto_sign_PUBLICKEYBYTES.should.have.type('number').above(0);
        sodium.crypto_sign_SECRETKEYBYTES.should.have.type('number').above(0);
        sodium.crypto_stream_KEYBYTES.should.have.type('number').above(0);
        sodium.crypto_stream_NONCEBYTES.should.have.type('number').above(0);
        done();
    });

    it('should fail to assign crypto_stream_NONCEBYTES', function(done) {
        (function() {
            sodium.crypto_stream_NONCEBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_stream_KEYBYTES', function(done) {
        (function() {
            sodium.crypto_stream_KEYBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_sign_SECRETKEYBYTES', function(done) {
        (function() {
            sodium.crypto_sign_SECRETKEYBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_sign_PUBLICKEYBYTES', function(done) {
        (function() {
            sodium.crypto_sign_PUBLICKEYBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_sign_BYTES', function(done) {
        (function() {
            sodium.crypto_sign_BYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_secretbox_ZEROBYTES', function(done) {
        (function() {
            sodium.crypto_secretbox_ZEROBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_secretbox_NONCEBYTES', function(done) {
        (function() {
            sodium.crypto_secretbox_NONCEBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_secretbox_KEYBYTES', function(done) {
        (function() {
            sodium.crypto_secretbox_KEYBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_onetimeauth_KEYBYTES', function(done) {
        (function() {
            sodium.crypto_onetimeauth_KEYBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_secretbox_BOXZEROBYTES', function(done) {
        (function() {
            sodium.crypto_secretbox_BOXZEROBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_onetimeauth_BYTES', function(done) {
        (function() {
            sodium.crypto_onetimeauth_BYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_hash_BYTES', function(done) {
        (function() {
            sodium.crypto_hash_BYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_box_ZEROBYTES', function(done) {
        (function() {
            sodium.crypto_box_ZEROBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_box_SECRETKEYBYTES', function(done) {
        (function() {
            sodium.crypto_box_SECRETKEYBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_box_PUBLICKEYBYTES', function(done) {
        (function() {
            sodium.crypto_box_PUBLICKEYBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_box_BOXZEROBYTES', function(done) {
        (function() {
            sodium.crypto_box_BOXZEROBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_box_BEFORENMBYTES', function(done) {
        (function() {
            sodium.crypto_box_BEFORENMBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_auth_KEYBYTES', function(done) {
        (function() {
            sodium.crypto_auth_KEYBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_box_NONCEBYTES', function(done) {
        (function() {
            sodium.crypto_box_NONCEBYTES = 0;
        }).should.throw();
        done();
    });

    it('should fail to assign crypto_auth_BYTES', function(done) {
        (function() {
            sodium.crypto_auth_BYTES = 0;
        }).should.throw();
        done();
    });
});
