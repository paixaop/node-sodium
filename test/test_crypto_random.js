/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var should = require('should');
var sodium = require('../build/Release/sodium');

describe('Randombytes', function() {
    it('should return a buffer of random numbers', function(done) {
        var buf = new Buffer(100);
        buf.fill(0);
        sodium.randombytes_buf(buf);

        var zeros = 0;
        for(var i=0; i<buf.length; i++) {
            if(!buf[i]) {
                zeros++;
            }
        }

        // If buf is all zeros then randombytes did not work!
        zeros.should.not.be.eql(buf.length);
        done();
    });

    it('random should generate a new number', function(done) {
        // Stir the pot and generate a new seed
        sodium.randombytes_stir();
        var r = sodium.randombytes_random() >>> 0;
        r.should.have.type('number').above(0);
        done();
    });

    it('uniform should generate a new number', function(done) {
        // Stir the pot and generate a new seed
        sodium.randombytes_stir();
        var r = sodium.randombytes_uniform(100) >>> 0;
        r.should.have.type('number').within(0,100);
        done();
    });

    it('should close file descriptor', function(done) {
        // Stir the pot and generate a new seed
        sodium.randombytes_stir();
        sodium.randombytes_close();
        done();
    });
});

describe("randombytes_buf verify parameters", function () {
    var buf = new Buffer(100);

    it('bad param 1 string', function(done) {
        buf = "token";
        (function() {
            sodium.randombytes_buf(buf);
        }).should.throw();
        done();
    });

    it('bad param 1 small number', function(done) {
        buf = 2;
        (function() {
            sodium.randombytes_buf(buf);
        }).should.throw();
        done();
    });
});
