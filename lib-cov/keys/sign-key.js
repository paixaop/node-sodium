if (typeof global.__coverage__ === 'undefined') { global.__coverage__ = {}; }
if (!global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/sign-key.js']) {
   global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/sign-key.js'] = {"path":"/Users/bmf/work/node-sodium/lib/keys/sign-key.js","s":{"1":0,"2":0,"3":0,"4":0,"5":0,"6":0,"7":0,"8":0,"9":0,"10":0,"11":0,"12":0,"13":0},"b":{},"f":{"1":0,"2":0},"fnMap":{"1":{"name":"(anonymous_1)","line":8,"loc":{"start":{"line":8,"column":11},"end":{"line":8,"column":52}}},"2":{"name":"(anonymous_2)","line":21,"loc":{"start":{"line":21,"column":20},"end":{"line":21,"column":31}}}},"statementMap":{"1":{"start":{"line":4,"column":0},"end":{"line":4,"column":27}},"2":{"start":{"line":5,"column":0},"end":{"line":5,"column":52}},"3":{"start":{"line":6,"column":0},"end":{"line":6,"column":35}},"4":{"start":{"line":8,"column":0},"end":{"line":26,"column":2}},"5":{"start":{"line":9,"column":4},"end":{"line":9,"column":20}},"6":{"start":{"line":11,"column":4},"end":{"line":11,"column":23}},"7":{"start":{"line":13,"column":4},"end":{"line":19,"column":7}},"8":{"start":{"line":21,"column":4},"end":{"line":25,"column":6}},"9":{"start":{"line":22,"column":8},"end":{"line":22,"column":49}},"10":{"start":{"line":23,"column":8},"end":{"line":23,"column":43}},"11":{"start":{"line":24,"column":8},"end":{"line":24,"column":43}},"12":{"start":{"line":27,"column":0},"end":{"line":27,"column":29}},"13":{"start":{"line":28,"column":0},"end":{"line":28,"column":22}}},"branchMap":{}};
}
var __cov_Ji_avF67LbdoE3qrK9Wd2w = global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/sign-key.js'];
__cov_Ji_avF67LbdoE3qrK9Wd2w.s['1']++;
var util = require('util');
__cov_Ji_avF67LbdoE3qrK9Wd2w.s['2']++;
var binding = require('../../build/Release/sodium');
__cov_Ji_avF67LbdoE3qrK9Wd2w.s['3']++;
var KeyPair = require('./keypair');
__cov_Ji_avF67LbdoE3qrK9Wd2w.s['4']++;
var Sign = function (publicKey, secretKey, encoding) {
    __cov_Ji_avF67LbdoE3qrK9Wd2w.f['1']++;
    __cov_Ji_avF67LbdoE3qrK9Wd2w.s['5']++;
    var self = this;
    __cov_Ji_avF67LbdoE3qrK9Wd2w.s['6']++;
    KeyPair.call(this);
    __cov_Ji_avF67LbdoE3qrK9Wd2w.s['7']++;
    self.init({
        publicKeySize: binding.crypto_sign_PUBLICKEYBYTES,
        secretKeySize: binding.crypto_sign_SECRETKEYBYTES,
        publicKey: publicKey,
        secretKey: secretKey,
        encoding: encoding
    });
    __cov_Ji_avF67LbdoE3qrK9Wd2w.s['8']++;
    self.generate = function () {
        __cov_Ji_avF67LbdoE3qrK9Wd2w.f['2']++;
        __cov_Ji_avF67LbdoE3qrK9Wd2w.s['9']++;
        var keys = binding.crypto_sign_keypair();
        __cov_Ji_avF67LbdoE3qrK9Wd2w.s['10']++;
        self.secretKey.set(keys.secretKey);
        __cov_Ji_avF67LbdoE3qrK9Wd2w.s['11']++;
        self.publicKey.set(keys.publicKey);
    };
};
__cov_Ji_avF67LbdoE3qrK9Wd2w.s['12']++;
util.inherits(Sign, KeyPair);
__cov_Ji_avF67LbdoE3qrK9Wd2w.s['13']++;
module.exports = Sign;
