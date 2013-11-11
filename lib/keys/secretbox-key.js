var util = require('util');
var binding = require('../../build/Release/sodium');
var CryptoBaseBuffer = require('../crypto-base-buffer');

var SecretBox = function(key, encoding) {
    var self = this;

    CryptoBaseBuffer.call(this);

    self.init(binding.crypto_onetimeauth_KEYBYTES, key, encoding);
    self.setValidEncodings(['hex', 'binary']);
};
util.inherits(SecretBox, CryptoBaseBuffer);
module.exports = SecretBox;