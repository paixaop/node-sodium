if (typeof global.__coverage__ === 'undefined') { global.__coverage__ = {}; }
if (!global.__coverage__['/Users/bmf/work/node-sodium/lib/auth.js']) {
   global.__coverage__['/Users/bmf/work/node-sodium/lib/auth.js'] = {"path":"/Users/bmf/work/node-sodium/lib/auth.js","s":{"1":0,"2":0,"3":0,"4":0,"5":0,"6":0,"7":0,"8":0,"9":0,"10":0,"11":0,"12":0,"13":0,"14":0,"15":0,"16":0,"17":0,"18":0,"19":0,"20":0,"21":0,"22":0,"23":0,"24":0,"25":0,"26":0,"27":0},"b":{"1":[0,0],"2":[0,0],"3":[0,0],"4":[0,0]},"f":{"1":0,"2":0,"3":0,"4":0,"5":0,"6":0},"fnMap":{"1":{"name":"(anonymous_1)","line":35,"loc":{"start":{"line":35,"column":11},"end":{"line":35,"column":41}}},"2":{"name":"(anonymous_2)","line":48,"loc":{"start":{"line":48,"column":15},"end":{"line":48,"column":26}}},"3":{"name":"(anonymous_3)","line":56,"loc":{"start":{"line":56,"column":23},"end":{"line":56,"column":42}}},"4":{"name":"(anonymous_4)","line":65,"loc":{"start":{"line":65,"column":23},"end":{"line":65,"column":34}}},"5":{"name":"(anonymous_5)","line":75,"loc":{"start":{"line":75,"column":20},"end":{"line":75,"column":48}}},"6":{"name":"(anonymous_6)","line":88,"loc":{"start":{"line":88,"column":20},"end":{"line":88,"column":55}}}},"statementMap":{"1":{"start":{"line":2,"column":0},"end":{"line":2,"column":49}},"2":{"start":{"line":3,"column":0},"end":{"line":3,"column":31}},"3":{"start":{"line":4,"column":0},"end":{"line":4,"column":41}},"4":{"start":{"line":5,"column":0},"end":{"line":5,"column":37}},"5":{"start":{"line":35,"column":0},"end":{"line":100,"column":2}},"6":{"start":{"line":36,"column":4},"end":{"line":36,"column":20}},"7":{"start":{"line":39,"column":4},"end":{"line":39,"column":37}},"8":{"start":{"line":42,"column":4},"end":{"line":42,"column":54}},"9":{"start":{"line":48,"column":4},"end":{"line":56,"column":4}},"10":{"start":{"line":49,"column":8},"end":{"line":49,"column":30}},"11":{"start":{"line":56,"column":4},"end":{"line":65,"column":4}},"12":{"start":{"line":57,"column":8},"end":{"line":57,"column":101}},"13":{"start":{"line":58,"column":8},"end":{"line":58,"column":40}},"14":{"start":{"line":65,"column":4},"end":{"line":75,"column":4}},"15":{"start":{"line":66,"column":8},"end":{"line":66,"column":36}},"16":{"start":{"line":75,"column":4},"end":{"line":79,"column":6}},"17":{"start":{"line":76,"column":8},"end":{"line":76,"column":52}},"18":{"start":{"line":77,"column":8},"end":{"line":77,"column":53}},"19":{"start":{"line":78,"column":8},"end":{"line":78,"column":69}},"20":{"start":{"line":88,"column":4},"end":{"line":99,"column":6}},"21":{"start":{"line":89,"column":8},"end":{"line":91,"column":9}},"22":{"start":{"line":90,"column":12},"end":{"line":90,"column":57}},"23":{"start":{"line":93,"column":8},"end":{"line":93,"column":52}},"24":{"start":{"line":95,"column":8},"end":{"line":95,"column":49}},"25":{"start":{"line":96,"column":8},"end":{"line":96,"column":53}},"26":{"start":{"line":98,"column":8},"end":{"line":98,"column":101}},"27":{"start":{"line":101,"column":0},"end":{"line":101,"column":22}}},"branchMap":{"1":{"line":76,"type":"binary-expr","locations":[{"start":{"line":76,"column":19},"end":{"line":76,"column":27}},{"start":{"line":76,"column":31},"end":{"line":76,"column":51}}]},"2":{"line":89,"type":"if","locations":[{"start":{"line":89,"column":8},"end":{"line":89,"column":8}},{"start":{"line":89,"column":8},"end":{"line":89,"column":8}}]},"3":{"line":93,"type":"binary-expr","locations":[{"start":{"line":93,"column":19},"end":{"line":93,"column":27}},{"start":{"line":93,"column":31},"end":{"line":93,"column":51}}]},"4":{"line":98,"type":"cond-expr","locations":[{"start":{"line":98,"column":88},"end":{"line":98,"column":93}},{"start":{"line":98,"column":96},"end":{"line":98,"column":100}}]}}};
}
var __cov_DnID65WCoKGmGx9igjQ46A = global.__coverage__['/Users/bmf/work/node-sodium/lib/auth.js'];
__cov_DnID65WCoKGmGx9igjQ46A.s['1']++;
var binding = require('../build/Release/sodium');
__cov_DnID65WCoKGmGx9igjQ46A.s['2']++;
var should = require('should');
__cov_DnID65WCoKGmGx9igjQ46A.s['3']++;
var AuthKey = require('./keys/auth-key');
__cov_DnID65WCoKGmGx9igjQ46A.s['4']++;
var toBuffer = require('./toBuffer');
__cov_DnID65WCoKGmGx9igjQ46A.s['5']++;
var Auth = function (secretKey, encoding) {
    __cov_DnID65WCoKGmGx9igjQ46A.f['1']++;
    __cov_DnID65WCoKGmGx9igjQ46A.s['6']++;
    var self = this;
    __cov_DnID65WCoKGmGx9igjQ46A.s['7']++;
    self.defaultEncoding = undefined;
    __cov_DnID65WCoKGmGx9igjQ46A.s['8']++;
    self.secretKey = new AuthKey(secretKey, encoding);
    __cov_DnID65WCoKGmGx9igjQ46A.s['9']++;
    self.key = function () {
        __cov_DnID65WCoKGmGx9igjQ46A.f['2']++;
        __cov_DnID65WCoKGmGx9igjQ46A.s['10']++;
        return self.secretKey;
    };
    __cov_DnID65WCoKGmGx9igjQ46A.s['11']++;
    self.setEncoding = function (encoding) {
        __cov_DnID65WCoKGmGx9igjQ46A.f['3']++;
        __cov_DnID65WCoKGmGx9igjQ46A.s['12']++;
        encoding.should.have.type('string').match(/^(?:utf8|ascii|binary|hex|utf16le|ucs2|base64)$/);
        __cov_DnID65WCoKGmGx9igjQ46A.s['13']++;
        self.defaultEncoding = encoding;
    };
    __cov_DnID65WCoKGmGx9igjQ46A.s['14']++;
    self.getEncoding = function () {
        __cov_DnID65WCoKGmGx9igjQ46A.f['4']++;
        __cov_DnID65WCoKGmGx9igjQ46A.s['15']++;
        return self.defaultEncoding;
    };
    __cov_DnID65WCoKGmGx9igjQ46A.s['16']++;
    self.generate = function (message, encoding) {
        __cov_DnID65WCoKGmGx9igjQ46A.f['5']++;
        __cov_DnID65WCoKGmGx9igjQ46A.s['17']++;
        encoding = (__cov_DnID65WCoKGmGx9igjQ46A.b['1'][0]++, encoding) || (__cov_DnID65WCoKGmGx9igjQ46A.b['1'][1]++, self.defaultEncoding);
        __cov_DnID65WCoKGmGx9igjQ46A.s['18']++;
        var messageBuf = toBuffer(message, encoding);
        __cov_DnID65WCoKGmGx9igjQ46A.s['19']++;
        return binding.crypto_auth(messageBuf, self.secretKey.get());
    };
    __cov_DnID65WCoKGmGx9igjQ46A.s['20']++;
    self.validate = function (token, message, encoding) {
        __cov_DnID65WCoKGmGx9igjQ46A.f['6']++;
        __cov_DnID65WCoKGmGx9igjQ46A.s['21']++;
        if (!self.secretKey) {
            __cov_DnID65WCoKGmGx9igjQ46A.b['2'][0]++;
            __cov_DnID65WCoKGmGx9igjQ46A.s['22']++;
            throw new Error('Auth: no secret key found');
        } else {
            __cov_DnID65WCoKGmGx9igjQ46A.b['2'][1]++;
        }
        __cov_DnID65WCoKGmGx9igjQ46A.s['23']++;
        encoding = (__cov_DnID65WCoKGmGx9igjQ46A.b['3'][0]++, encoding) || (__cov_DnID65WCoKGmGx9igjQ46A.b['3'][1]++, self.defaultEncoding);
        __cov_DnID65WCoKGmGx9igjQ46A.s['24']++;
        var tokenBuf = toBuffer(token, encoding);
        __cov_DnID65WCoKGmGx9igjQ46A.s['25']++;
        var messageBuf = toBuffer(message, encoding);
        __cov_DnID65WCoKGmGx9igjQ46A.s['26']++;
        return binding.crypto_auth_verify(tokenBuf, messageBuf, self.secretKey.get()) ? (__cov_DnID65WCoKGmGx9igjQ46A.b['4'][0]++, false) : (__cov_DnID65WCoKGmGx9igjQ46A.b['4'][1]++, true);
    };
};
__cov_DnID65WCoKGmGx9igjQ46A.s['27']++;
module.exports = Auth;
