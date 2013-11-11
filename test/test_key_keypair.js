/**
 * Created by bmf on 11/2/13.
 */
var should = require('should');
var crypto = require('crypto');

var Key = require('../lib/keys/keypair');
if (process.env.COVERAGE) {
    Key = require('../lib-cov/keys/keypair');
}

describe("KeyPair", function () {
    it('generate should throw', function(done) {
        var key = new Key();
        (function() {
            key.init();
        }).should.throw();
        done();
    });

    it('generate should throw', function(done) {
        var key = new Key();
        (function() {
            key.generate();
        }).should.throw();
        done();
    });

});