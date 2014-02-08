/**
 * Created by bmf on 11/2/13.
 */
var should = require('should');

var toBuffer = require('../lib/toBuffer');

if (process.env.COVERAGE) {
    toBuffer = require('../lib-cov/toBuffer');
}


describe("toBuffer", function () {
    it("should generate a buffer from string", function (done) {
        var str = "to buffer is cool";
        toBuffer(str,'utf8').toString().should.eql("to buffer is cool");
        done();
    });

    it("should generate a buffer from string with encoding", function (done) {
        var str = "to buffer is cool";
        toBuffer(str, 'utf8').toString().should.eql("to buffer is cool");
        done();
    });

    it("should return undefined on bad param 1", function (done) {
        (function() {
            var b = toBuffer(123, 'utf8');
        }).should.throw();
        done();
    });

    it("should throw on bad encoding", function (done) {
        var str = "to buffer is cool";
        (function() {
            toBuffer(str, 'txf');
        }).should.throw();
        done();
    });

    it("should generate a buffer from array", function (done) {
        var a = [1, 2, 3, 4, 5];
        var b = toBuffer(a);
        for( var i = 0 ; i < b.length; i++ ) {
            b[i].should.eql(a[i]);
        }
        done();
    });

    it("Generate a buffer from buffer!", function (done) {
        var a = new Buffer(5);
        a.fill(5);
        var b = toBuffer(a);
        for( var i = 0 ; i < b.length; i++ ) {
            b[i].should.eql(a[i]);
        }
        done();
    });


});