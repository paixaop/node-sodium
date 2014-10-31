/**
 * Created by bmf on 11/2/13.
 */
var should = require('should');
var sodium = require('../build/Release/sodium');

var Box = require('../lib/box2');
if (process.env.COVERAGE) {
    Box = require('../lib-cov/box2');
}

describe("Box", function () {
    it("encrypt/decrypt and validate message", function (done) {
        var box = new Box();
        var cipherBox = box.encrypt("This is a test", "utf8");
        box.decrypt(cipherBox, "utf8").should.eql("This is a test");
        done();
    });

});