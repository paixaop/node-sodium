/**
 * Created by bmf on 11/2/13.
 */
var should = require('should');
var sodium = require('../build/Release/sodium');

var Sign = require('../lib/sign');
if (process.env.COVERAGE) {
    Sign = require('../lib-cov/sign');
}

describe("Sign", function () {
    it("sign/verify message", function (done) {
        var sign = new Sign();
        var message = new Buffer("This is a test", 'utf8');
        var signedMsg = sign.sign("This is a test", 'utf8');
        var checkMsg = Sign.verify(signedMsg);
        checkMsg.toString('utf8').should.eql("This is a test");
        done();
    });
});