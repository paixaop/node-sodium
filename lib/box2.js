/**
 * Created by bmf on 11/2/13.
 *
 * Documentation of crypto http://nacl.cr.yp.to/box.html
 */
var binding = require('../build/Release/sodium');
var should = require('should');
var toBuffer = require('./toBuffer');
var CryptoBase = require('./crypto-base');
var Nonce = require('./nonces/box-nonce');
var util = require('util');

/**
 * Public-key authenticated encryption: Box
 *
 * @param {String|Buffer|Array} secretKey sender's private key.
 * @param {String|Buffer|Array} publicKey recipient's private key.
 *
 * @see Keys
 * @constructor
 */
var Box = function(publicKey, secretKey) {
    var self = this;

    CryptoBase.call(this);

    self.init({
        secretKey: secretKey,
        publicKey: publicKey,
        keyModule: 'box-key',
        keyPair: true
    });

    /**
     * Encrypt a message
     *
     * @param {Buffer|String|Array} plainText  message to encrypt
     * @param {String} [encoding]             encoding of message string
     *
     * @returns {Object}                       cipher box
     */
    self.encrypt = function (plainText, encoding) {
        var encoding = String(encoding) || self.defaultEncoding || 'utf8';

        // generate a new random nonce
        var nonce = new Nonce();

        var buf = toBuffer(plainText, encoding);

        var cipherText = binding.crypto_box(
            buf,
            nonce.get(),
            self.iKey.getPublicKey().get(),
            self.iKey.getSecretKey().get());

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
        encoding = String(encoding || self.defaultEncoding || 'utf8');

        cipherBox.should.have.type('object').properties('cipherText', 'nonce');
        cipherBox.cipherText.should.be.an.instanceof.Buffer;
        cipherBox.nonce.should.be.an.instanceof.Buffer;
        cipherBox.nonce.should.have.length(binding.crypto_box_NONCEBYTES);

        var nonce = new Nonce(cipherBox.nonce);

        var plainText = binding.crypto_box_open(
            cipherBox.cipherText,
            nonce.get(),
            self.iKey.getPublicKey().get(),
            self.iKey.getSecretKey().get()
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

