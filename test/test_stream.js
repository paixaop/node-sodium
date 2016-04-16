/**
 * Created by bmf on 11/2/13.
 */
var should = require('should');
var sodium = require('../build/Release/sodium');

var Stream = require('../lib/stream');
if (process.env.COVERAGE) {
    Stream = require('../lib-cov/stream');
}

describe("Stream", function () {
    it("encryp/decrypt message", function (done) {
        var stream = new Stream();

        var cTxt = stream.encrypt("This is a test", "utf8");
        var checkMsg = stream.decrypt(cTxt);
        checkMsg.toString('utf8').should.eql("This is a test");
        done();
    });

    it("should return a stream buffer", function (done) {
        var stream = new Stream();

        var s = stream.generate(100);
        s.should.have.type('object').with.properties("stream", "nonce");
        s.stream.should.have.length(100);
        s.nonce.should.have.length(sodium.crypto_stream_NONCEBYTES);
        done();
    });

});