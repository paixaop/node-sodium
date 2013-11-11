/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var should = require('should');
var crypto = require('crypto');
var sodium = require('../build/Release/sodium');

describe('Auth', function() {
    it('should return a token', function(done) {
        var buf = new Buffer(100);
        buf.fill(1);
        var key = new Buffer(sodium.crypto_auth_KEYBYTES);
        key.fill(0);
        key[0] = 9;
        key[1] = 9;
        var r = sodium.crypto_auth(buf, key);
        var token = r.toString('hex');
        token.should.eql("22b4c0615f736278655b8e8e7f63bda982f2c96c661c7d34e1d63488bd6c9df9");
        done();
    });

    it('should validate', function(done) {
        var buf = crypto.randomBytes(256);
        var key = crypto.randomBytes(sodium.crypto_auth_KEYBYTES);
        var token = sodium.crypto_auth(buf, key);
        var r = sodium.crypto_auth_verify(token, buf, key);
        r.should.eql(0);
        done();
    });
});

describe('crypto_auth check paramters', function() {
    var buf = crypto.randomBytes(256);
    var key = crypto.randomBytes(sodium.crypto_auth_KEYBYTES);

    it('check param 1', function(done) {
        var b = "buf";
        var k = key;
        (function() {
            var token = sodium.crypto_auth(b, k);
        }).should.throw();

        b = 5;
        (function() {
            var token = sodium.crypto_auth(b, k);
        }).should.throw();
        done();
    });

    it('check param 2', function(done) {
        var b = buf;
        var k = "key";
        (function() {
            var token = sodium.crypto_auth(b, k);
        }).should.throw();

        k = new Buffer(5);
        (function() {
            var token = sodium.crypto_auth(b, k);
        }).should.throw();

        k = 5;
        (function() {
            var token = sodium.crypto_auth(b, k);
        }).should.throw();
        done();
    });

});

describe('crypto_auth_verify check paramters', function() {
    var buf = crypto.randomBytes(256);
    var key = crypto.randomBytes(sodium.crypto_auth_KEYBYTES);
    var token = sodium.crypto_auth(buf, key);

    it('check param 1', function(done) {
        var t = "token";
        var b = buf;
        var k = key;

        (function() {
            var r = sodium.crypto_auth_verify(t, b, k);
        }).should.throw();

        t = new Buffer(5);
        (function() {
            var r = sodium.crypto_auth_verify(t, b, k);
        }).should.throw();

        t = 5;
        (function() {
            var r = sodium.crypto_auth_verify(t, b, k);
        }).should.throw();

        done();
    });

    it('check param 2', function(done) {
        var t = token;
        var b = "buf";
        var k = key;

        (function() {
            var r = sodium.crypto_auth_verify(t, b, k);
        }).should.throw();

        b = 5;
        (function() {
            var r = sodium.crypto_auth_verify(t, b, k);
        }).should.throw();

        done();
    });

    it('check param 3', function(done) {
        var t = token;
        var b = buf;
        var k = "key";

        (function() {
            var r = sodium.crypto_auth_verify(t, b, k);
        }).should.throw();

        k = new Buffer(5);
        (function() {
            var r = sodium.crypto_auth_verify(t, b, k);
        }).should.throw();

        k = 5;
        (function() {
            var r = sodium.crypto_auth_verify(t, b, k);
        }).should.throw();

        done();
    });

});
