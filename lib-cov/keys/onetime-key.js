if (typeof global.__coverage__ === 'undefined') { global.__coverage__ = {}; }
if (!global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/onetime-key.js']) {
   global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/onetime-key.js'] = {"path":"/Users/bmf/work/node-sodium/lib/keys/onetime-key.js","s":{"1":0,"2":0,"3":0,"4":0,"5":0,"6":0,"7":0,"8":0,"9":0,"10":0},"b":{},"f":{"1":0},"fnMap":{"1":{"name":"(anonymous_1)","line":8,"loc":{"start":{"line":8,"column":14},"end":{"line":8,"column":38}}}},"statementMap":{"1":{"start":{"line":4,"column":0},"end":{"line":4,"column":27}},"2":{"start":{"line":5,"column":0},"end":{"line":5,"column":52}},"3":{"start":{"line":6,"column":0},"end":{"line":6,"column":56}},"4":{"start":{"line":8,"column":0},"end":{"line":15,"column":2}},"5":{"start":{"line":9,"column":4},"end":{"line":9,"column":20}},"6":{"start":{"line":11,"column":4},"end":{"line":11,"column":32}},"7":{"start":{"line":13,"column":4},"end":{"line":13,"column":66}},"8":{"start":{"line":14,"column":4},"end":{"line":14,"column":46}},"9":{"start":{"line":16,"column":0},"end":{"line":16,"column":41}},"10":{"start":{"line":17,"column":0},"end":{"line":17,"column":25}}},"branchMap":{}};
}
var __cov_eCEoluL1R2kyupToY$b8Ew = global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/onetime-key.js'];
__cov_eCEoluL1R2kyupToY$b8Ew.s['1']++;
var util = require('util');
__cov_eCEoluL1R2kyupToY$b8Ew.s['2']++;
var binding = require('../../build/Release/sodium');
__cov_eCEoluL1R2kyupToY$b8Ew.s['3']++;
var CryptoBaseBuffer = require('../crypto-base-buffer');
__cov_eCEoluL1R2kyupToY$b8Ew.s['4']++;
var OneTime = function (key, encoding) {
    __cov_eCEoluL1R2kyupToY$b8Ew.f['1']++;
    __cov_eCEoluL1R2kyupToY$b8Ew.s['5']++;
    var self = this;
    __cov_eCEoluL1R2kyupToY$b8Ew.s['6']++;
    CryptoBaseBuffer.call(this);
    __cov_eCEoluL1R2kyupToY$b8Ew.s['7']++;
    self.init(binding.crypto_onetimeauth_KEYBYTES, key, encoding);
    __cov_eCEoluL1R2kyupToY$b8Ew.s['8']++;
    self.setValidEncodings([
        'hex',
        'binary'
    ]);
};
__cov_eCEoluL1R2kyupToY$b8Ew.s['9']++;
util.inherits(OneTime, CryptoBaseBuffer);
__cov_eCEoluL1R2kyupToY$b8Ew.s['10']++;
module.exports = OneTime;
