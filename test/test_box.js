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

    it("encrypt should throw if no first argument", function () {
        var box = new Box();
        (function() {
            box.decrypt();
        }).should.throw();
    });

    it("encrypt should throw if the first argument is not an object with `cipherText` and `nonce` properties", function () {
        var box = new Box();
        (function() {
            box.decrypt({});
        }).should.throw();
        (function() {
            box.decrypt({cipherText: new Buffer('foo')});
        }).should.throw();
        (function() {
            box.decrypt({nonce: 'bar'});
        }).should.throw();
    });

    it("encrypt show throw if cipherBox.cipherText is not a buffer", function () {
        var box = new Box();
        (function() {
            box.decrypt({cipherText: "not a buffer", nonce: "foo"});
        }).should.throw();
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

    it('should set an encoding if a supported encoding is passed to setEncoding', function() {
        var box = new Box();
        box.setEncoding('base64');
        box.defaultEncoding.should.equal('base64');
    });

    it('should fail to set an encoding if an unsupported encoding is passed to setEncoding', function() {
        var box = new Box();
        (function () {
            box.setEncoding('unsupported-encoding');
        }).should.throw();
    });
});
