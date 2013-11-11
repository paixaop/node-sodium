/**
 * Created by bmf on 11/2/13.
 */
var util = require('util');
var binding = require('../../build/Release/sodium');
var CryptoBaseBuffer = require('../crypto-base-buffer');

var OneTime = function(key, encoding) {
    var self = this;

    CryptoBaseBuffer.call(this);

    self.init(binding.crypto_onetimeauth_KEYBYTES, key, encoding);
    self.setValidEncodings(['hex', 'binary']);
};
util.inherits(OneTime, CryptoBaseBuffer);
module.exports = OneTime;