if (typeof global.__coverage__ === 'undefined') { global.__coverage__ = {}; }
if (!global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/secretbox-key.js']) {
   global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/secretbox-key.js'] = {"path":"/Users/bmf/work/node-sodium/lib/keys/secretbox-key.js","s":{"1":0,"2":0,"3":0,"4":0,"5":0,"6":0,"7":0,"8":0,"9":0,"10":0},"b":{},"f":{"1":0},"fnMap":{"1":{"name":"(anonymous_1)","line":5,"loc":{"start":{"line":5,"column":16},"end":{"line":5,"column":40}}}},"statementMap":{"1":{"start":{"line":1,"column":0},"end":{"line":1,"column":27}},"2":{"start":{"line":2,"column":0},"end":{"line":2,"column":52}},"3":{"start":{"line":3,"column":0},"end":{"line":3,"column":56}},"4":{"start":{"line":5,"column":0},"end":{"line":12,"column":2}},"5":{"start":{"line":6,"column":4},"end":{"line":6,"column":20}},"6":{"start":{"line":8,"column":4},"end":{"line":8,"column":32}},"7":{"start":{"line":10,"column":4},"end":{"line":10,"column":66}},"8":{"start":{"line":11,"column":4},"end":{"line":11,"column":46}},"9":{"start":{"line":13,"column":0},"end":{"line":13,"column":43}},"10":{"start":{"line":14,"column":0},"end":{"line":14,"column":27}}},"branchMap":{}};
}
var __cov_JOV6a9JJ9dorKgZjIjMW8Q = global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/secretbox-key.js'];
__cov_JOV6a9JJ9dorKgZjIjMW8Q.s['1']++;
var util = require('util');
__cov_JOV6a9JJ9dorKgZjIjMW8Q.s['2']++;
var binding = require('../../build/Release/sodium');
__cov_JOV6a9JJ9dorKgZjIjMW8Q.s['3']++;
var CryptoBaseBuffer = require('../crypto-base-buffer');
__cov_JOV6a9JJ9dorKgZjIjMW8Q.s['4']++;
var SecretBox = function (key, encoding) {
    __cov_JOV6a9JJ9dorKgZjIjMW8Q.f['1']++;
    __cov_JOV6a9JJ9dorKgZjIjMW8Q.s['5']++;
    var self = this;
    __cov_JOV6a9JJ9dorKgZjIjMW8Q.s['6']++;
    CryptoBaseBuffer.call(this);
    __cov_JOV6a9JJ9dorKgZjIjMW8Q.s['7']++;
    self.init(binding.crypto_onetimeauth_KEYBYTES, key, encoding);
    __cov_JOV6a9JJ9dorKgZjIjMW8Q.s['8']++;
    self.setValidEncodings([
        'hex',
        'binary'
    ]);
};
__cov_JOV6a9JJ9dorKgZjIjMW8Q.s['9']++;
util.inherits(SecretBox, CryptoBaseBuffer);
__cov_JOV6a9JJ9dorKgZjIjMW8Q.s['10']++;
module.exports = SecretBox;
