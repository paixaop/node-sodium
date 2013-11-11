if (typeof global.__coverage__ === 'undefined') { global.__coverage__ = {}; }
if (!global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/auth-key.js']) {
   global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/auth-key.js'] = {"path":"/Users/bmf/work/node-sodium/lib/keys/auth-key.js","s":{"1":0,"2":0,"3":0,"4":0,"5":0,"6":0,"7":0,"8":0,"9":0,"10":0},"b":{},"f":{"1":0},"fnMap":{"1":{"name":"(anonymous_1)","line":13,"loc":{"start":{"line":13,"column":11},"end":{"line":13,"column":35}}}},"statementMap":{"1":{"start":{"line":4,"column":0},"end":{"line":4,"column":27}},"2":{"start":{"line":5,"column":0},"end":{"line":5,"column":52}},"3":{"start":{"line":6,"column":0},"end":{"line":6,"column":56}},"4":{"start":{"line":13,"column":0},"end":{"line":20,"column":2}},"5":{"start":{"line":14,"column":4},"end":{"line":14,"column":20}},"6":{"start":{"line":16,"column":4},"end":{"line":16,"column":32}},"7":{"start":{"line":18,"column":4},"end":{"line":18,"column":59}},"8":{"start":{"line":19,"column":4},"end":{"line":19,"column":46}},"9":{"start":{"line":21,"column":0},"end":{"line":21,"column":38}},"10":{"start":{"line":22,"column":0},"end":{"line":22,"column":22}}},"branchMap":{}};
}
var __cov_J4naU6N4xAlxmsCCvrQbeA = global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/auth-key.js'];
__cov_J4naU6N4xAlxmsCCvrQbeA.s['1']++;
var util = require('util');
__cov_J4naU6N4xAlxmsCCvrQbeA.s['2']++;
var binding = require('../../build/Release/sodium');
__cov_J4naU6N4xAlxmsCCvrQbeA.s['3']++;
var CryptoBaseBuffer = require('../crypto-base-buffer');
__cov_J4naU6N4xAlxmsCCvrQbeA.s['4']++;
var Auth = function (key, encoding) {
    __cov_J4naU6N4xAlxmsCCvrQbeA.f['1']++;
    __cov_J4naU6N4xAlxmsCCvrQbeA.s['5']++;
    var self = this;
    __cov_J4naU6N4xAlxmsCCvrQbeA.s['6']++;
    CryptoBaseBuffer.call(this);
    __cov_J4naU6N4xAlxmsCCvrQbeA.s['7']++;
    self.init(binding.crypto_auth_KEYBYTES, key, encoding);
    __cov_J4naU6N4xAlxmsCCvrQbeA.s['8']++;
    self.setValidEncodings([
        'hex',
        'binary'
    ]);
};
__cov_J4naU6N4xAlxmsCCvrQbeA.s['9']++;
util.inherits(Auth, CryptoBaseBuffer);
__cov_J4naU6N4xAlxmsCCvrQbeA.s['10']++;
module.exports = Auth;
