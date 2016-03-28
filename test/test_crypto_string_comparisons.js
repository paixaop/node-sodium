/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var should = require('should');
var sodium = require('../build/Release/sodium');

describe('String Comparison', function() {
    it('crypto_verify_16 throw with strings smaller than 16 bytes', function(done) {
        var string1 = new Buffer("1234", "ascii");
        var string2 = new Buffer("1234", "ascii");
        (function() {
            var r = sodium.crypto_verify_16(string1, string2);
        }).should.throw();
        done();
    });

    it('crypto_verify_16 should return 0 when strings are equal', function(done) {
        var string1 = new Buffer("0123456789ABCDEF", "ascii");
        var string2 = new Buffer("0123456789ABCDEF", "ascii");
        var r = sodium.crypto_verify_16(string1, string2);
        r.should.be.eql(0);
        done();
    });

    it('crypto_verify_16 should return -1 when strings are different', function(done) {
        var string1 = new Buffer("0123456789ABCDEF", "ascii");
        var string2 = new Buffer("0023456789ABCDEF", "ascii");
        var r = sodium.crypto_verify_16(string1, string2);
        r.should.be.eql(-1);
        done();
    });

    it('crypto_verify_32 throw with strings smaller than 32 bytes', function(done) {
        var string1 = new Buffer("1234", "ascii");
        var string2 = new Buffer("1234", "ascii");
        (function() {
            var r = sodium.crypto_verify_32(string1, string2);
        }).should.throw();
        done();
    });

    it('crypto_verify_32 should return 0 when strings are equal', function(done) {
        var string1 = new Buffer("0123456789ABCDEF0123456789ABCDEF", "ascii");
        var string2 = new Buffer("0123456789ABCDEF0123456789ABCDEF", "ascii");
        var r = sodium.crypto_verify_32(string1, string2);
        r.should.be.eql(0);
        done();
    });

    it('crypto_verify_32 return -1 when strings are different', function(done) {
        var string1 = new Buffer("0123456789ABCDEF0123456789ABCDEF", "ascii");
        var string2 = new Buffer("0023456789ABCDEF0123456789ABCDEF", "ascii");
        var r = sodium.crypto_verify_32(string1, string2);
        r.should.be.eql(-1);
        done();
    });
});

describe("crypto_verify_32 verify parameters", function () {
    var string1 = new Buffer("0123456789ABCDEF0123456789ABCDEF", "ascii");
    var string2 = new Buffer("0123456789ABCDEF0123456789ABCDEF", "ascii");

    it('bad param 1 string', function(done) {
        string1 = "123";
        (function() {
            var r = sodium.crypto_verify_32(string1, string2);
        }).should.throw();
        done();
    });

    it('bad param 1 number', function(done) {
        string1 = 123;
        (function() {
            var r = sodium.crypto_verify_32(string1, string2);
        }).should.throw();
        done();
    });

    it('bad param 2 string', function(done) {
        string2 = "123";
        (function() {
            var r = sodium.crypto_verify_32(string1, string2);
        }).should.throw();
        done();
    });

    it('bad param 2 number', function(done) {
        string2 = 123;
        (function() {
            var r = sodium.crypto_verify_32(string1, string2);
        }).should.throw();
        done();
    });
});

describe("crypto_verify_16 verify parameters", function () {
    var string1 = new Buffer("0123456789ABCDEF0123456789ABCDEF", "ascii");
    var string2 = new Buffer("0123456789ABCDEF0123456789ABCDEF", "ascii");

    it('bad param 1 string', function(done) {
        string1 = "123";
        (function() {
            var r = sodium.crypto_verify_16(string1, string2);
        }).should.throw();
        done();
    });

    it('bad param 1 number', function(done) {
        string1 = 123;
        (function() {
            var r = sodium.crypto_verify_16(string1, string2);
        }).should.throw();
        done();
    });

    it('bad param 2 string', function(done) {
        string2 = "123";
        (function() {
            var r = sodium.crypto_verify_16(string1, string2);
        }).should.throw();
        done();
    });

    it('bad param 2 number', function(done) {
        string2 = 123;
        (function() {
            var r = sodium.crypto_verify_16(string1, string2);
        }).should.throw();
        done();
    });
});