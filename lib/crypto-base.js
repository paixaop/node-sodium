/**
 * Created by bmf on 11/2/13.
 *
 * Documentation of crypto http://nacl.cr.yp.to/box.html
 */
var binding = require('../build/Release/sodium');
var should = require('should');

var CryptoBase = function() {
    var self = this;

    self.iKey = undefined;

    /**
     * Init object
     * @param {Object} options
     * @param {String} options.keyModule  name of module in keys directory
     * @param {Boolean} options.keyPair   if true we're using the key pair class
     * @param {String|Buffer|Array} options.publicKey  public key to init the key class
     * @param {String|Buffer|Array} options.secretKey  secret key to init the key class
     */
    self.init = function(options) {
        options = options || {};
        try {
            var Key = require('./keys/' + options.keyModule);
            if( options.keyPair ) {
                self.iKey = new Key(options.secretKey, options.publicKey);
            }
            else {
                self.iKey = new Key(options.secretKey);
            }
        }
        catch (e) {
            throw new Error('[CryptoBase] invalid module');
        }
    }

    /** default encoding to use in all string operations */
    self.defaultEncoding = undefined;

    /**
     * Get the box-key secret keypair object
     * @returns {BoxKey|*}
     */
    self.key = function() {
        if( !self.iKey ) {
            throw new Error('[CryptoBase] call init() before calling other methods');
        }
        return self.iKey;
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
     * Encrypt a message
     * The encrypt function encrypts and authenticates a message using the
     * sender's secret key, the receiver's public key, and a nonce n.
     *
     * If no options are given a new random nonce will be generated automatically
     * and both planText and cipherText must be buffers
     *
     * options.encoding is optional and specifies the encoding of the plainText
     * nonce, and cipherText if they are passed as strings. If plainText and
     * nonce are buffers, options.encoding will only affect the resulting
     * cipherText.
     * The basic API leaves it up to the
     * caller to generate a unique nonce for every message, in the high level
     * API a random nonce is generated automatically and you do no need to
     * worry about it.
     *
     * @param {Buffer|String|Array} plainText  message to encrypt
     * @param {String} [encoding]             encoding of message string
     *
     * @returns {Object}                       cipher box
     */
    self.encrypt = function (plainText, encoding) {
       throw new Error('[CryptoBase] this method must be called from sub class');
    };

    /**
     * The decrypt function verifies and decrypts a cipherText using the
     * receiver's secret key, the sender's public key, and a nonce.
     * The function returns the resulting plaintext m.
     *
     * @param {Buffer|String|Array} cipherText  the encrypted message
     * @param {Buffer|String|Array} nonce       the nonce used to encrypt
     * @param {String} [encoding]               the encoding to used in cipherText, nonce, plainText
     */
    self.decrypt = function (cipherBox, encoding) {
        throw new Error('[CryptoBase] this method must be called from sub class');
    };

    // Aliases
    self.close = self.encrypt;
    self.open = self.decrypt;
};
module.exports = CryptoBase;

