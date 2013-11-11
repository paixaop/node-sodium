/**
 * Created by bmf on 11/2/13.
 *
 * Documentation of crypto http://nacl.cr.yp.to/box.html
 */
var binding = require('../build/Release/sodium');
var should = require('should');
var toBuffer = require('./tobuffer');
var CryptoBase = require('./crypto-base');
var Nonce = require('./nonces/box-nonce');
var util = require('util');
var BoxKey = require('./keys/box-key');

/**
 * Public-key authenticated encryption: Box
 *
 * @param {String|Buffer|Array} secretKey sender's private key.
 * @param {String|Buffer|Array} publicKey recipient's private key.
 *
 * @see Keys
 * @constructor
 */
var Box = function(secretKey, publicKey) {
    var self = this;

    CryptoBase.call(this);

    self.iKey = new BoxKey(secretKey, publicKey);


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
        var encoding = encoding || self.defaultEncoding;

        // generate a new random nonce
        var nonce = new Nonce();

        var buf = toBuffer(plainText, encoding);

        var cipherText = binding.crypto_box(
            buf,
            nonce.get(),
            self.boxKey.getPublicKey().get(),
            self.boxKey.getSecretKey().get());

        if( !cipherText ) {
            return undefined;
        }

        return {
            cipherText: cipherText,
            nonce : nonce.get()
        };
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
        encoding = String(encoding || self.defaultEncoding);

        cipherBox.should.have.type('object').properties('cipherText', 'nonce');
        cipherBox.cipherText.should.be.an.instanceof.Buffer;

        var nonce = new Nonce(cipherBox.nonce);

        var plainText = binding.crypto_box_open(
            cipherBox.cipherText,
            nonce.get(),
            self.boxKey.getPublicKey().get(),
            self.boxKey.getSecretKey().get()
        );

        if( encoding ) {
            return plainText.toString(encoding);
        }

        return plainText;
    };

    // Aliases
    self.close = self.encrypt;
    self.open = self.decrypt;
};
util.inherits(Box, CryptoBase);
module.exports = Box;

