var util = require('util');
var binding = require('../../build/Release/sodium');
var CryptoBaseBuffer = require('../crypto-base-buffer');

var Stream = function(key, encoding) {
    var self = this;

    CryptoBaseBuffer.call(this);

    self.init(binding.crypto_stream_KEYBYTES, key, encoding);
    self.setValidEncodings(['hex', 'base64']);
};

util.inherits(Stream, CryptoBaseBuffer);
module.exports = Stream;