/**
 * Created by bmf on 11/2/13.
 */
var should = require('should');
var sodium = require('../build/Release/sodium');

// Test all KeyPair classes
testKey('box-key',sodium.crypto_box_PUBLICKEYBYTES, sodium.crypto_box_SECRETKEYBYTES);
testKey('sign-key',sodium.crypto_sign_PUBLICKEYBYTES, sodium.crypto_sign_SECRETKEYBYTES);
testKey('dh-key',sodium.crypto_scalarmult_BYTES, sodium.crypto_scalarmult_BYTES);

function testKey(modName,sizePkBuffer, sizeSkBuffer) {
    var KeyPair = require('../lib/keys/' + modName);
    if (process.env.COVERAGE) {
        KeyPair = require('../lib-cov/keys/' + modName);
    }

    describe(modName, function () {
        it("generate a valid key", function (done) {
            var key = new KeyPair();
            key.generate();
            var k = key.get();
            key.isValid(k).should.be.ok;
            done();
        });

        it("key size should match that of sodium", function (done) {
            var key = new KeyPair();
            key.getPublicKey().size().should.eql(sizePkBuffer);
            key.getSecretKey().size().should.eql(sizeSkBuffer);
            done();
        });
        
        it("key bytes should match that of sodium", function (done) {
            var key = new KeyPair();
            key.publicKeyBytes().should.eql(sizePkBuffer);
            key.secretKeyBytes().should.eql(sizeSkBuffer);
            done();
        });
        
        it("key bytes should match that of sodium", function (done) {
            var key = new KeyPair();
            key.pkBytes().should.eql(sizePkBuffer);
            key.skBytes().should.eql(sizeSkBuffer);
            done();
        });

        it("isValid should return false on bad key", function (done) {
            var key = new KeyPair();
            var k = {
                publicKey: new Buffer(2),
                secretKey: new Buffer(2)
            };
            key.isValid(k).should.not.be.ok;
            done();
        });

        it("toString should return a string!", function (done) {
            var key = new KeyPair();
            key.toString().should.have.type('string');
            done();
        });

        it("toString should return a string!", function (done) {
            var key = new KeyPair();
            var k = key.get();

            key.toString('hex').should.match(/[0-9a-f]+,[0-9A-F]+/i);
            done();
        });

        it("toString should throw with bad encoding!", function (done) {
            var key = new KeyPair();
            (function() {
                key.toString('utf8');
            }).should.throw();

            done();
        });

        it("key test string encoding utf8 should throw", function (done) {
            var key = new KeyPair();
            (function() {
                var n = key.toString('utf8');
                key.set(n, 'utf8');
            }).should.throw();
            done();
        });

        it("key test string encoding base64 should throw", function (done) {
            var key = new KeyPair();
            (function() {
                var n = key.toString('base64');
                key.set(n, 'base64');
            }).should.throw();
            done();
        });

    });
}