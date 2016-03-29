/**
 * Created by bmf on 03/28/16.
 */
"use strict";

var should = require('should');
var sodium = require('../build/Release/sodium');

describe('LargeNumbers', function() {
    it('should increment a zero filled buffer to 3 after 3 calls', function(done) {
        var buf = new Buffer(10);
        buf.fill(0);
        sodium.increment(buf,10);
        sodium.increment(buf,10);
        sodium.increment(buf,10);
        
        var zeros = 0;
        buf[0].should.be.eql(3);
        for(var i=1; i<buf.length; i++) {
            buf[i].should.be.eql(0);
        }
        
        done();
    });
    
     it('should add two buffers', function(done) {
        var buf1 = new Buffer(10);
        var buf2 = new Buffer(10);
        
        sodium.randombytes_buf(buf1);
        
        
        var zeros = 0;
        buf[0].should.be.eql(3);
        for(var i=1; i<buf.length; i++) {
            buf[i].should.be.eql(0);
        }
        
        done();
    });
});
