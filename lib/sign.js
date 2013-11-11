/**
 * Created by bmf on 11/2/13.
 *
 * Documentation of crypto http://nacl.cr.yp.to/box.html
 */
var binding = require('../build/Release/sodium');
var should = require('should');
var SignKey = require('./keys/sign-key');
var toBuffer = require('../lib/tobuffer');


/**
 * Public-key authenticated message signatures: Sign
 *
 * @param {String|Buffer|Array} secretKey sender's private key.
 * @param {String|Buffer|Array} publicKey recipient's private key.
 *
 * @see Keys
 * @constructor
 */
var Sign = function(publicKey, secretKey) {
    var self = this;

    /** default encoding to use in all string operations */
    self.defaultEncoding = undefined;

    /** Set of keys used to encrypt and decrypt messages */
    self.iKey = new SignKey(publicKey, secretKey);

    /**
     * Get the keypair object
     * @returns {SignKey|*}
     */
    self.key = function() {
        return self.iKey;
    }

    /**
     * @return {Number} The size of the message signature
     */
    self.size = function() {
        return binding.crypto_sign_BYTES;
    }

    /**
     * Set the default encoding to use in all string conversions
     * @param {String} encoding  encoding to use
     */
    self.setEncoding = function(encoding) {
        encoding.should.have.type('string').match(/^(?:utf8|ascii|binary|hex|utf16le|ucs2|base64)$/);
        self.defaultEncoding = encoding;
    }

    /**
     * Get the current default encoding
     * @returns {undefined|String}
     */
    self.getEncoding = function() {
        return self.defaultEncoding;
    }

    /**
     * Digitally sign message
     *
     * @param {Buffer|String|Array} message  message to sign
     * @param {String} [encoding]             encoding of message string
     *
     * @returns {Object}                       cipher box
     */
    self.sign = function (message, encoding) {
        var encoding = encoding || self.defaultEncoding;

        var buf = toBuffer(message, encoding);

        return binding.crypto_sign(buf, self.iKey.getSecretKey().get());
    };

    /**
     * Verify digital signature
     *
     * @param {Buffer|String|Array} cipherText  the signed message
     */
    self.verify = function (signature) {
        return binding.crypto_sign_open(signature, self.iKey.getPublicKey().get());
    };
};
module.exports = Sign;

