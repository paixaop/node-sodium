/**
 * Created by bmf on 11/2/13.
 */
var should = require('should');
var sodium = require('../build/Release/sodium');

var Box = require('../lib/box');
if (process.env.COVERAGE) {
    Box = require('../lib-cov/box');
}

describe("Box", function () {
    it("encrypt/decrypt and validate message", function (done) {
        var box = new Box();
        box.setEncoding('utf8');
        var cipherBox = box.encrypt("This is a test");
        box.decrypt(cipherBox).should.eql("This is a test");
        done();
    });

    it("encrypt should return a valid cipherbox", function (done) {
        var box = new Box();
        box.setEncoding('utf8');
        var cipherBox = box.encrypt("This is a test");
        cipherBox.should.have.type('object').with.properties('cipherText', 'nonce');
        cipherBox.cipherText.should.be.instanceof.Buffer;
        cipherBox.nonce.should.be.instanceof.Buffer;
        done();
    });

    it("key size should match that of sodium", function (done) {
        var box = new Box();
        box.key().getPublicKey().size().should.eql(sodium.crypto_box_PUBLICKEYBYTES);
        box.key().getSecretKey().size().should.eql(sodium.crypto_box_SECRETKEYBYTES);
        done();
    });

    it("generate throw on a bad cipherBox buffer", function (done) {
        var box = new Box();
        var cipherBox = box.encrypt("This is a test", 'utf8');

        cipherBox.cipherText[0] = 99;
        cipherBox.cipherText[1] = 99;
        cipherBox.cipherText[2] = 99;
        (function() {
            box.decrypt(cipherBox);
        }).should.throw();
        done();
    });

    it("generate throw on a bad cipherBox buffer", function (done) {
        var box = new Box();
        var cipherBox = box.encrypt("This is a test", 'utf8');

        cipherBox.cipherText[18] = 99;
        cipherBox.cipherText[19] = 99;
        cipherBox.cipherText[20] = 99;
        (function() {
            box.decrypt(cipherBox);
        }).should.throw();
        done();
    });

    it("set bad secretKey should fail", function (done) {
        var box = new Box();

        (function() {
            box.set(new Buffer(2));
        }).should.throw();

        done();
    });

    it("set/get secretKey", function (done) {
        var box = new Box();

        box.key().generate();
        var k = box.key().get();

        var auth2 = new Box();
        auth2.key().set(k);

        k2 = auth2.key().get();

        k2.should.eql(k);

        done();
    });

});