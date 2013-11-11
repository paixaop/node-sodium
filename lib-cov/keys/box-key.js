if (typeof global.__coverage__ === 'undefined') { global.__coverage__ = {}; }
if (!global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/box-key.js']) {
   global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/box-key.js'] = {"path":"/Users/bmf/work/node-sodium/lib/keys/box-key.js","s":{"1":0,"2":0,"3":0,"4":0,"5":0,"6":0,"7":0,"8":0,"9":0,"10":0,"11":0,"12":0,"13":0},"b":{},"f":{"1":0,"2":0},"fnMap":{"1":{"name":"(anonymous_1)","line":8,"loc":{"start":{"line":8,"column":10},"end":{"line":8,"column":51}}},"2":{"name":"(anonymous_2)","line":20,"loc":{"start":{"line":20,"column":20},"end":{"line":20,"column":31}}}},"statementMap":{"1":{"start":{"line":4,"column":0},"end":{"line":4,"column":27}},"2":{"start":{"line":5,"column":0},"end":{"line":5,"column":52}},"3":{"start":{"line":6,"column":0},"end":{"line":6,"column":35}},"4":{"start":{"line":8,"column":0},"end":{"line":25,"column":2}},"5":{"start":{"line":9,"column":4},"end":{"line":9,"column":20}},"6":{"start":{"line":11,"column":4},"end":{"line":11,"column":23}},"7":{"start":{"line":13,"column":4},"end":{"line":18,"column":7}},"8":{"start":{"line":20,"column":4},"end":{"line":24,"column":6}},"9":{"start":{"line":21,"column":8},"end":{"line":21,"column":48}},"10":{"start":{"line":22,"column":8},"end":{"line":22,"column":43}},"11":{"start":{"line":23,"column":8},"end":{"line":23,"column":43}},"12":{"start":{"line":26,"column":0},"end":{"line":26,"column":28}},"13":{"start":{"line":27,"column":0},"end":{"line":27,"column":21}}},"branchMap":{}};
}
var __cov_aVpaguidrLXJkFLy8muXsQ = global.__coverage__['/Users/bmf/work/node-sodium/lib/keys/box-key.js'];
__cov_aVpaguidrLXJkFLy8muXsQ.s['1']++;
var util = require('util');
__cov_aVpaguidrLXJkFLy8muXsQ.s['2']++;
var binding = require('../../build/Release/sodium');
__cov_aVpaguidrLXJkFLy8muXsQ.s['3']++;
var KeyPair = require('./keypair');
__cov_aVpaguidrLXJkFLy8muXsQ.s['4']++;
var Box = function (publicKey, secretKey, encoding) {
    __cov_aVpaguidrLXJkFLy8muXsQ.f['1']++;
    __cov_aVpaguidrLXJkFLy8muXsQ.s['5']++;
    var self = this;
    __cov_aVpaguidrLXJkFLy8muXsQ.s['6']++;
    KeyPair.call(this);
    __cov_aVpaguidrLXJkFLy8muXsQ.s['7']++;
    self.init({
        publicKeySize: binding.crypto_box_PUBLICKEYBYTES,
        secretKeySize: binding.crypto_box_SECRETKEYBYTES,
        publicKey: publicKey,
        secretKey: secretKey
    });
    __cov_aVpaguidrLXJkFLy8muXsQ.s['8']++;
    self.generate = function () {
        __cov_aVpaguidrLXJkFLy8muXsQ.f['2']++;
        __cov_aVpaguidrLXJkFLy8muXsQ.s['9']++;
        var keys = binding.crypto_box_keypair();
        __cov_aVpaguidrLXJkFLy8muXsQ.s['10']++;
        self.secretKey.set(keys.secretKey);
        __cov_aVpaguidrLXJkFLy8muXsQ.s['11']++;
        self.publicKey.set(keys.publicKey);
    };
};
__cov_aVpaguidrLXJkFLy8muXsQ.s['12']++;
util.inherits(Box, KeyPair);
__cov_aVpaguidrLXJkFLy8muXsQ.s['13']++;
module.exports = Box;
