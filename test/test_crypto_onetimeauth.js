/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var should = require('should');
var crypto = require('crypto');
var sodium = require('../build/Release/sodium');

describe('OneTimeAuth', function() {
    it('should validate', function(done) {
        var buf = crypto.randomBytes(256);
        var key = crypto.randomBytes(sodium.crypto_auth_KEYBYTES);
        var token = sodium.crypto_onetimeauth(buf, key);
        var r = sodium.crypto_onetimeauth_verify(token, buf, key);
        r.should.eql(0);
        done();
    });
});

describe('crypto_onetimeauth verify parameters', function() {
    var buf = crypto.randomBytes(256);
    var key = crypto.randomBytes(sodium.crypto_auth_KEYBYTES);

    it('bad param 1 string', function(done) {
        buf = "123";
        (function() {
            var token = sodium.crypto_onetimeauth(buf, key);
        }).should.throw();
        done();
    });

    it('bad param 1 number', function(done) {
        buf = 123;
        (function() {
            var token = sodium.crypto_onetimeauth(buf, key);
        }).should.throw();
        done();
    });

    it('bad param 2 string', function(done) {
        key = "123";
        (function() {
            var token = sodium.crypto_onetimeauth(buf, key);
        }).should.throw();
        done();
    });

    it('bad param 2 buffer', function(done) {
        key = new Buffer(2);
        (function() {
            var token = sodium.crypto_onetimeauth(buf, key);
        }).should.throw();
        done();
    });

    it('bad param 2 number', function(done) {
        key = 123;
        (function() {
            var token = sodium.crypto_onetimeauth(buf, key);
        }).should.throw();
        done();
    });
});

describe('crypto_onetimeauth_verify verify parameters', function() {
    var buf = crypto.randomBytes(256);
    var key = crypto.randomBytes(sodium.crypto_auth_KEYBYTES);
    var token = sodium.crypto_onetimeauth(buf, key);

    it('bad param 1 string', function(done) {
        token = "token";
        (function() {
            var r = sodium.crypto_onetimeauth_verify(token, buf, key);
        }).should.throw();
        done();
    });

    it('bad param 1 small buffer', function(done) {
        token = new Buffer(2);
        (function() {
            var r = sodium.crypto_onetimeauth_verify(token, buf, key);
        }).should.throw();
        done();
    });

    it('bad param 1 small number', function(done) {
        token = 2;
        (function() {
            var r = sodium.crypto_onetimeauth_verify(token, buf, key);
        }).should.throw();
        done();
    });

    it('bad param 2 string', function(done) {
        buf = "qweqw";
        (function() {
            var r = sodium.crypto_onetimeauth_verify(token, buf, key);
        }).should.throw();
        done();
    });

    it('bad param 2 small number', function(done) {
        buf = 1;
        (function() {
            var r = sodium.crypto_onetimeauth_verify(token, buf, key);
        }).should.throw();
        done();
    });

    it('bad param 3 string', function(done) {
        key = "qweqw";
        (function() {
            var r = sodium.crypto_onetimeauth_verify(token, buf, key);
        }).should.throw();
        done();
    });

    it('bad param 3 buffer', function(done) {
        key = new Buffer(2);
        (function() {
            var r = sodium.crypto_onetimeauth_verify(token, buf, key);
        }).should.throw();
        done();
    });

    it('bad param 3 small number', function(done) {
        key = 1;
        (function() {
            var r = sodium.crypto_onetimeauth_verify(token, buf, key);
        }).should.throw();
        done();
    });
});
