/**
 * Created by bmf on 10/31/13.
 */
"use strict";

var should = require('should');
var sodium = require('../build/Release/sodium');

describe('Version', function() {
    it('should return a string', function(done) {
        var v = sodium.sodium_version_string();
        v.should.have.type('string');
        done();
    })

    it('Minor should return an integer', function(done) {
        sodium.sodium_library_version_minor().should.have.type('number');
        done();
    });

    it('Major should return an integer', function(done) {
        sodium.sodium_library_version_major().should.have.type('number');
        done();
    });
});
