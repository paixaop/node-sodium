/**
 * Created by bmf on 11/2/13.
 */
var should = require('should');
var sodium = require('../build/Release/sodium');

var Auth = require('../lib/auth');
if (process.env.COVERAGE) {
    Auth = require('../lib-cov/auth');
}

describe("Auth", function () {
    it("generate token and validate message", function (done) {
        var auth = new Auth();
        var token = auth.generate("This is a test", 'utf8');

        auth.validate(token, "This is a test", 'utf8').should.be.ok;
        done();
    });

    it("key size should match that of sodium", function (done) {
        var auth = new Auth();
        auth.key().size().should.eql(sodium.crypto_auth_KEYBYTES);
        done();
    });

    it("generate return false on a bad token", function (done) {
        var auth = new Auth();
        auth.key().generate();
        var token = auth.generate("This is a test", 'utf8');

        token[0] = 99;
        token[1] = 99;
        token[2] = 99;

        auth.validate(token, "This is a test", 'utf8').should.not.be.ok;
        done();
    });

    it("set bad secretKey should fail", function (done) {
        var auth = new Auth();

        (function() {
            auth.set(new Buffer(2));
        }).should.throw();

        done();
    });

    it("set/get secretKey", function (done) {
        var auth = new Auth();

        auth.key().generate();
        var k = auth.key().get();

        var auth2 = new Auth();
        auth2.key().set(k);

        k2 = auth2.key().get();

        k2.should.eql(k);

        done();
    });

    it('should fail call generate before having a key', function() {
        var auth = new Auth();
        (function() {
            auth.generate("123");
        }).should.throw();
    });

    it('should fail call validate before having a key', function() {
        var auth = new Auth();
        (function() {
            auth.validate("123123", "123123");
        }).should.throw();
    });
});