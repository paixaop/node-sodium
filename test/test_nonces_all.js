/**
 * Created by bmf on 11/2/13.
 */
var should = require('should');
var sodium = require('../build/Release/sodium');

// Test all nonce classes

testNonce('box-nonce',sodium.crypto_box_NONCEBYTES);
testNonce('secretbox-nonce',sodium.crypto_secretbox_NONCEBYTES);
testNonce('stream-nonce',sodium.crypto_stream_NONCEBYTES);

function testNonce(modName, sizeBuffer) {
    var Nonce = require('../lib/nonces/' + modName);
    if (process.env.COVERAGE) {
        Nonce = require('../lib-cov/nonces/' + modName);
    }

    describe("stream-nonce", function () {
        it("generate a valid nonce", function (done) {
            var nonce = new Nonce();
            nonce.generate();
            var k = nonce.get();
            nonce.isValid(k).should.be.ok;
            done();
        });

        it("nonce test string encoding utf8 should throw", function (done) {
            var nonce = new Nonce();
            (function() {
                var n = nonce.toString('utf8');
                nonce.set(n, 'utf8');
            }).should.throw();
            done();
        });

        it("nonce test string encoding hex", function (done) {
            var nonce = new Nonce();
            var n = nonce.toString('hex');
            nonce.set(n, 'hex');
            done();
        });

        it("nonce test string encoding base64 should throw", function (done) {
            var nonce = new Nonce();
            var n = nonce.toString('base64');
            nonce.set(n, 'base64');
            done();
        });

        it("nonce test string encoding binary", function (done) {
            var nonce = new Nonce();
            (function() {
                var n = nonce.toString('binary');
                nonce.set(n, 'binary');
            }).should.throw();

            done();
        });

        it("nonce test string encoding ascii should throw", function (done) {
            var nonce = new Nonce();
            (function() {
                var n = nonce.toString('ascii');
                nonce.set(n, 'ascii');
            }).should.throw();
            done();
        });

        it("nonce test string encoding utf16le should throw", function (done) {
            var nonce = new Nonce();
            (function() {
                var n = nonce.toString('utf16le');
                nonce.set(n, 'utf16le');
            }).should.throw();
            done();
        });

        it("nonce test string encoding ucs2 should throw", function (done) {
            var nonce = new Nonce();
            (function() {
                var n = nonce.toString('ucs2');
                nonce.set(n, 'ucs2');
            }).should.throw();
            done();
        });

        it("nonce size should match that of sodium", function (done) {
            var nonce = new Nonce();
            nonce.size().should.eql(sizeBuffer);
            done();
        });
        
        it("nonce size should match that of sodium", function (done) {
            var nonce = new Nonce();
            nonce.bytes().should.eql(sizeBuffer);
            done();
        });

        it("isValid should return false on bad nonce", function (done) {
            var nonce = new Nonce();
            var k = new Buffer(2);
            nonce.isValid(k).should.not.be.ok;
            done();
        });

        it("isValid should return false on bad hex string", function (done) {
            var nonce = new Nonce();
            nonce.isValid("123").should.not.be.ok;
            done();
        });

        it("isValid should return false on bad nonce type", function (done) {
            var nonce = new Nonce();
            nonce.isValid(123).should.not.be.ok;
            done();
        });

        it("isValid should return true on hex string", function (done) {
            var nonce = new Nonce();
            nonce.generate();
            var k = nonce.get();
            nonce.isValid(k.toString('hex'),'hex').should.be.ok;
            done();
        });

        it("isValid should return throw on bad encoding string", function (done) {
            var nonce = new Nonce();
            nonce.generate();
            var k = nonce.get();
            (function() {
                nonce.isValid(k.toString('hex'),'sex').should.be.ok;
            }).should.throw();
            done();
        });

        it("reset should zero out the nonce", function (done) {
            var nonce = new Nonce();
            nonce.generate();
            nonce.wipe();
            var k = nonce.get();
            for(var i = 0; i < k.length; i++ ) {
                k[i].should.eql(0);
            }
            done();
        });

        it("set should throw on bad nonce length", function (done) {
            var nonce = new Nonce();
            (function() {
                nonce.set(new Buffer(2));
            }).should.throw();
            done();
        });

        it("set/get secretNonce", function (done) {
            var nonce = new Nonce();

            nonce.generate();
            var k = nonce.get();

            var nonce2 = new Nonce();
            nonce2.set(k);

            k2 = nonce2.get();

            k2.should.eql(k);

            done();
        });

        it("toString should return a string!", function (done) {
            var nonce = new Nonce();
            nonce.generate();
            nonce.toString().should.have.type('string');
            done();
        });

        it("toString should return a string!", function (done) {
            var nonce = new Nonce();
            nonce.generate();
            var k = nonce.get();
            nonce.toString('hex').should.eql(k.toString('hex'));
            done();
        });

        it("toString should throw with bad encoding!", function (done) {
            var nonce = new Nonce();
            (function() {
                nonce.toString('sex');
            }).should.throw();

            done();
        });
    });
}