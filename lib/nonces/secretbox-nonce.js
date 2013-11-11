/**
 * Created by bmf on 11/3/13.
 */
var util = require('util');
var binding = require('../../build/Release/sodium');
var CryptoBaseBuffer = require('../crypto-base-buffer');

var SecretBox = function(nonce, encoding) {
    var self = this;

    CryptoBaseBuffer.call(this);

    self.setValidEncodings(['hex', 'base64']);

    self.init(binding.crypto_secretbox_NONCEBYTES, nonce, encoding);
};
util.inherits(SecretBox, CryptoBaseBuffer);
module.exports = SecretBox;