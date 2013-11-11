/**
 * Created by bmf on 11/2/13.
 */
var util = require('util');
var binding = require('../../build/Release/sodium');
var CryptoBaseBuffer = require('../crypto-base-buffer');

/**
 * Message Authentication Secret Key
 *
 * @param {String|Buffer|Array} key secret key
 */
var Auth = function(key, encoding) {
    var self = this;

    CryptoBaseBuffer.call(this);

    self.init(binding.crypto_auth_KEYBYTES, key, encoding);
    self.setValidEncodings(['hex', 'binary']);
};
util.inherits(Auth, CryptoBaseBuffer);
module.exports = Auth;