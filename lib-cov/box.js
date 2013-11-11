if (typeof global.__coverage__ === 'undefined') { global.__coverage__ = {}; }
if (!global.__coverage__['/Users/bmf/work/node-sodium/lib/box.js']) {
   global.__coverage__['/Users/bmf/work/node-sodium/lib/box.js'] = {"path":"/Users/bmf/work/node-sodium/lib/box.js","s":{"1":0,"2":0,"3":0,"4":0,"5":0,"6":0,"7":0,"8":0,"9":0,"10":0,"11":0,"12":0,"13":0,"14":0,"15":0,"16":0,"17":0,"18":0,"19":0,"20":0,"21":0,"22":0,"23":0,"24":0,"25":0,"26":0,"27":0,"28":0,"29":0,"30":0,"31":0,"32":0,"33":0,"34":0,"35":0,"36":0},"b":{"1":[0,0],"2":[0,0],"3":[0,0],"4":[0,0]},"f":{"1":0,"2":0,"3":0,"4":0,"5":0,"6":0},"fnMap":{"1":{"name":"(anonymous_1)","line":22,"loc":{"start":{"line":22,"column":10},"end":{"line":22,"column":41}}},"2":{"name":"(anonymous_2)","line":35,"loc":{"start":{"line":35,"column":15},"end":{"line":35,"column":26}}},"3":{"name":"(anonymous_3)","line":43,"loc":{"start":{"line":43,"column":23},"end":{"line":43,"column":42}}},"4":{"name":"(anonymous_4)","line":52,"loc":{"start":{"line":52,"column":23},"end":{"line":52,"column":34}}},"5":{"name":"(anonymous_5)","line":78,"loc":{"start":{"line":78,"column":19},"end":{"line":78,"column":50}}},"6":{"name":"(anonymous_6)","line":111,"loc":{"start":{"line":111,"column":19},"end":{"line":111,"column":50}}}},"statementMap":{"1":{"start":{"line":6,"column":0},"end":{"line":6,"column":49}},"2":{"start":{"line":7,"column":0},"end":{"line":7,"column":31}},"3":{"start":{"line":8,"column":0},"end":{"line":8,"column":37}},"4":{"start":{"line":9,"column":0},"end":{"line":9,"column":39}},"5":{"start":{"line":10,"column":0},"end":{"line":10,"column":42}},"6":{"start":{"line":22,"column":0},"end":{"line":136,"column":2}},"7":{"start":{"line":23,"column":4},"end":{"line":23,"column":20}},"8":{"start":{"line":26,"column":4},"end":{"line":26,"column":37}},"9":{"start":{"line":29,"column":4},"end":{"line":29,"column":51}},"10":{"start":{"line":35,"column":4},"end":{"line":43,"column":4}},"11":{"start":{"line":36,"column":8},"end":{"line":36,"column":27}},"12":{"start":{"line":43,"column":4},"end":{"line":52,"column":4}},"13":{"start":{"line":44,"column":8},"end":{"line":44,"column":101}},"14":{"start":{"line":45,"column":8},"end":{"line":45,"column":40}},"15":{"start":{"line":52,"column":4},"end":{"line":78,"column":4}},"16":{"start":{"line":53,"column":8},"end":{"line":53,"column":36}},"17":{"start":{"line":78,"column":4},"end":{"line":100,"column":6}},"18":{"start":{"line":79,"column":8},"end":{"line":79,"column":56}},"19":{"start":{"line":82,"column":8},"end":{"line":82,"column":32}},"20":{"start":{"line":84,"column":8},"end":{"line":84,"column":48}},"21":{"start":{"line":86,"column":8},"end":{"line":90,"column":46}},"22":{"start":{"line":92,"column":8},"end":{"line":94,"column":9}},"23":{"start":{"line":93,"column":12},"end":{"line":93,"column":29}},"24":{"start":{"line":96,"column":8},"end":{"line":99,"column":10}},"25":{"start":{"line":111,"column":4},"end":{"line":131,"column":6}},"26":{"start":{"line":112,"column":8},"end":{"line":112,"column":60}},"27":{"start":{"line":114,"column":8},"end":{"line":114,"column":79}},"28":{"start":{"line":115,"column":8},"end":{"line":115,"column":60}},"29":{"start":{"line":117,"column":8},"end":{"line":117,"column":47}},"30":{"start":{"line":119,"column":8},"end":{"line":124,"column":10}},"31":{"start":{"line":126,"column":8},"end":{"line":128,"column":9}},"32":{"start":{"line":127,"column":12},"end":{"line":127,"column":48}},"33":{"start":{"line":130,"column":8},"end":{"line":130,"column":25}},"34":{"start":{"line":134,"column":4},"end":{"line":134,"column":30}},"35":{"start":{"line":135,"column":4},"end":{"line":135,"column":29}},"36":{"start":{"line":137,"column":0},"end":{"line":137,"column":21}}},"branchMap":{"1":{"line":79,"type":"binary-expr","locations":[{"start":{"line":79,"column":23},"end":{"line":79,"column":31}},{"start":{"line":79,"column":35},"end":{"line":79,"column":55}}]},"2":{"line":92,"type":"if","locations":[{"start":{"line":92,"column":8},"end":{"line":92,"column":8}},{"start":{"line":92,"column":8},"end":{"line":92,"column":8}}]},"3":{"line":112,"type":"binary-expr","locations":[{"start":{"line":112,"column":26},"end":{"line":112,"column":34}},{"start":{"line":112,"column":38},"end":{"line":112,"column":58}}]},"4":{"line":126,"type":"if","locations":[{"start":{"line":126,"column":8},"end":{"line":126,"column":8}},{"start":{"line":126,"column":8},"end":{"line":126,"column":8}}]}}};
}
var __cov_AFi3Hztip0mlcvsuunbGJw = global.__coverage__['/Users/bmf/work/node-sodium/lib/box.js'];
__cov_AFi3Hztip0mlcvsuunbGJw.s['1']++;
var binding = require('../build/Release/sodium');
__cov_AFi3Hztip0mlcvsuunbGJw.s['2']++;
var should = require('should');
__cov_AFi3Hztip0mlcvsuunbGJw.s['3']++;
var toBuffer = require('./tobuffer');
__cov_AFi3Hztip0mlcvsuunbGJw.s['4']++;
var BoxKey = require('./keys/box-key');
__cov_AFi3Hztip0mlcvsuunbGJw.s['5']++;
var Nonce = require('./nonces/box-nonce');
__cov_AFi3Hztip0mlcvsuunbGJw.s['6']++;
var Box = function (secretKey, publicKey) {
    __cov_AFi3Hztip0mlcvsuunbGJw.f['1']++;
    __cov_AFi3Hztip0mlcvsuunbGJw.s['7']++;
    var self = this;
    __cov_AFi3Hztip0mlcvsuunbGJw.s['8']++;
    self.defaultEncoding = undefined;
    __cov_AFi3Hztip0mlcvsuunbGJw.s['9']++;
    self.boxKey = new BoxKey(publicKey, secretKey);
    __cov_AFi3Hztip0mlcvsuunbGJw.s['10']++;
    self.key = function () {
        __cov_AFi3Hztip0mlcvsuunbGJw.f['2']++;
        __cov_AFi3Hztip0mlcvsuunbGJw.s['11']++;
        return self.boxKey;
    };
    __cov_AFi3Hztip0mlcvsuunbGJw.s['12']++;
    self.setEncoding = function (encoding) {
        __cov_AFi3Hztip0mlcvsuunbGJw.f['3']++;
        __cov_AFi3Hztip0mlcvsuunbGJw.s['13']++;
        encoding.should.have.type('string').match(/^(?:utf8|ascii|binary|hex|utf16le|ucs2|base64)$/);
        __cov_AFi3Hztip0mlcvsuunbGJw.s['14']++;
        self.defaultEncoding = encoding;
    };
    __cov_AFi3Hztip0mlcvsuunbGJw.s['15']++;
    self.getEncoding = function () {
        __cov_AFi3Hztip0mlcvsuunbGJw.f['4']++;
        __cov_AFi3Hztip0mlcvsuunbGJw.s['16']++;
        return self.defaultEncoding;
    };
    __cov_AFi3Hztip0mlcvsuunbGJw.s['17']++;
    self.encrypt = function (plainText, encoding) {
        __cov_AFi3Hztip0mlcvsuunbGJw.f['5']++;
        __cov_AFi3Hztip0mlcvsuunbGJw.s['18']++;
        var encoding = (__cov_AFi3Hztip0mlcvsuunbGJw.b['1'][0]++, encoding) || (__cov_AFi3Hztip0mlcvsuunbGJw.b['1'][1]++, self.defaultEncoding);
        __cov_AFi3Hztip0mlcvsuunbGJw.s['19']++;
        var nonce = new Nonce();
        __cov_AFi3Hztip0mlcvsuunbGJw.s['20']++;
        var buf = toBuffer(plainText, encoding);
        __cov_AFi3Hztip0mlcvsuunbGJw.s['21']++;
        var cipherText = binding.crypto_box(buf, nonce.get(), self.boxKey.getPublicKey().get(), self.boxKey.getSecretKey().get());
        __cov_AFi3Hztip0mlcvsuunbGJw.s['22']++;
        if (!cipherText) {
            __cov_AFi3Hztip0mlcvsuunbGJw.b['2'][0]++;
            __cov_AFi3Hztip0mlcvsuunbGJw.s['23']++;
            return undefined;
        } else {
            __cov_AFi3Hztip0mlcvsuunbGJw.b['2'][1]++;
        }
        __cov_AFi3Hztip0mlcvsuunbGJw.s['24']++;
        return {
            cipherText: cipherText,
            nonce: nonce.get()
        };
    };
    __cov_AFi3Hztip0mlcvsuunbGJw.s['25']++;
    self.decrypt = function (cipherBox, encoding) {
        __cov_AFi3Hztip0mlcvsuunbGJw.f['6']++;
        __cov_AFi3Hztip0mlcvsuunbGJw.s['26']++;
        encoding = String((__cov_AFi3Hztip0mlcvsuunbGJw.b['3'][0]++, encoding) || (__cov_AFi3Hztip0mlcvsuunbGJw.b['3'][1]++, self.defaultEncoding));
        __cov_AFi3Hztip0mlcvsuunbGJw.s['27']++;
        cipherBox.should.have.type('object').properties('cipherText', 'nonce');
        __cov_AFi3Hztip0mlcvsuunbGJw.s['28']++;
        cipherBox.cipherText.should.be.an.instanceof.Buffer;
        __cov_AFi3Hztip0mlcvsuunbGJw.s['29']++;
        var nonce = new Nonce(cipherBox.nonce);
        __cov_AFi3Hztip0mlcvsuunbGJw.s['30']++;
        var plainText = binding.crypto_box_open(cipherBox.cipherText, nonce.get(), self.boxKey.getPublicKey().get(), self.boxKey.getSecretKey().get());
        __cov_AFi3Hztip0mlcvsuunbGJw.s['31']++;
        if (encoding) {
            __cov_AFi3Hztip0mlcvsuunbGJw.b['4'][0]++;
            __cov_AFi3Hztip0mlcvsuunbGJw.s['32']++;
            return plainText.toString(encoding);
        } else {
            __cov_AFi3Hztip0mlcvsuunbGJw.b['4'][1]++;
        }
        __cov_AFi3Hztip0mlcvsuunbGJw.s['33']++;
        return plainText;
    };
    __cov_AFi3Hztip0mlcvsuunbGJw.s['34']++;
    self.close = self.encrypt;
    __cov_AFi3Hztip0mlcvsuunbGJw.s['35']++;
    self.open = self.decrypt;
};
__cov_AFi3Hztip0mlcvsuunbGJw.s['36']++;
module.exports = Box;
