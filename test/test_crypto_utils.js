/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var should = require('should');
var sodium = require('../build/Release/sodium');

describe('Utils', function() {
    it('should zero a buffer', function(done) {
        var buf = new Buffer(100);
        buf.fill(1);
        sodium.memzero(buf);
        for(var i=0; i< buf.length; i++) {
            buf[i].should.eql(0);
        }
        done();
    });
});

describe("memzero verify parameters", function () {
    var buf = new Buffer(100);
    it('bad param 1 string', function(done) {
        buf = "token";
        (function() {
            sodium.memzero(buf);
        }).should.throw();
        done();
    });
    it('bad param 1 number', function(done) {
        buf = 123;
        (function() {
            sodium.memzero(buf);
        }).should.throw();
        done();
    });
});