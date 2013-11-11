if (typeof global.__coverage__ === 'undefined') { global.__coverage__ = {}; }
if (!global.__coverage__['/Users/bmf/work/node-sodium/lib/nonces/stream-nonce.js']) {
   global.__coverage__['/Users/bmf/work/node-sodium/lib/nonces/stream-nonce.js'] = {"path":"/Users/bmf/work/node-sodium/lib/nonces/stream-nonce.js","s":{"1":0,"2":0,"3":0,"4":0,"5":0,"6":0,"7":0,"8":0,"9":0,"10":0},"b":{},"f":{"1":0},"fnMap":{"1":{"name":"(anonymous_1)","line":8,"loc":{"start":{"line":8,"column":13},"end":{"line":8,"column":39}}}},"statementMap":{"1":{"start":{"line":4,"column":0},"end":{"line":4,"column":27}},"2":{"start":{"line":5,"column":0},"end":{"line":5,"column":52}},"3":{"start":{"line":6,"column":0},"end":{"line":6,"column":56}},"4":{"start":{"line":8,"column":0},"end":{"line":16,"column":2}},"5":{"start":{"line":9,"column":4},"end":{"line":9,"column":20}},"6":{"start":{"line":11,"column":4},"end":{"line":11,"column":32}},"7":{"start":{"line":13,"column":4},"end":{"line":13,"column":46}},"8":{"start":{"line":15,"column":4},"end":{"line":15,"column":65}},"9":{"start":{"line":17,"column":0},"end":{"line":17,"column":40}},"10":{"start":{"line":18,"column":0},"end":{"line":18,"column":24}}},"branchMap":{}};
}
var __cov_tKpqwdijR4xWxRTs1PwtPg = global.__coverage__['/Users/bmf/work/node-sodium/lib/nonces/stream-nonce.js'];
__cov_tKpqwdijR4xWxRTs1PwtPg.s['1']++;
var util = require('util');
__cov_tKpqwdijR4xWxRTs1PwtPg.s['2']++;
var binding = require('../../build/Release/sodium');
__cov_tKpqwdijR4xWxRTs1PwtPg.s['3']++;
var CryptoBaseBuffer = require('../crypto-base-buffer');
__cov_tKpqwdijR4xWxRTs1PwtPg.s['4']++;
var Stream = function (nonce, encoding) {
    __cov_tKpqwdijR4xWxRTs1PwtPg.f['1']++;
    __cov_tKpqwdijR4xWxRTs1PwtPg.s['5']++;
    var self = this;
    __cov_tKpqwdijR4xWxRTs1PwtPg.s['6']++;
    CryptoBaseBuffer.call(this);
    __cov_tKpqwdijR4xWxRTs1PwtPg.s['7']++;
    self.setValidEncodings([
        'hex',
        'base64'
    ]);
    __cov_tKpqwdijR4xWxRTs1PwtPg.s['8']++;
    self.init(binding.crypto_stream_NONCEBYTES, nonce, encoding);
};
__cov_tKpqwdijR4xWxRTs1PwtPg.s['9']++;
util.inherits(Stream, CryptoBaseBuffer);
__cov_tKpqwdijR4xWxRTs1PwtPg.s['10']++;
module.exports = Stream;
