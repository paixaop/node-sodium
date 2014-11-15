/**
 * Created by bmf on 11/2/13.
 *
 * Documentation of crypto http://nacl.cr.yp.to/box.html
 */
 /* jslint node: true */
'use strict';

var binding = require('../build/Release/sodium');
var SignKey = require('./keys/sign-key');
var toBuffer = require('./toBuffer');


/**
 * Public-key authenticated message signatures: Sign
 *
 * @param {String|Buffer|Array} secretKey sender's private key.
 * @param {String|Buffer|Array} publicKey recipient's private key.
 *
 * @see Keys
 * @constructor
 */
function Sign(key) {
    var self = this;

    /** default encoding to use in all string operations */
    self.defaultEncoding = undefined;

    if( key instanceof SignKey) {
        self.iKey = key;
    }
    else {
        /** Set of keys used to encrypt and decrypt messages */
        self.iKey = new SignKey();
    }

    /** Size of the generated message signature */
    self.bytes = function() {
        return binding.crypto_sign_BYTES;
    };

    /** String name of the default crypto primitive used in sign operations */
    self.primitive = function() {
        return binding.crypto_sign_PRIMITIVE;
    };

    /**
     * Get the keypair object
     * @returns {SignKey|*}
     */
    self.key = function() {
        return self.iKey;
    };

    /**
     * @return {Number} The size of the message signature
     */
    self.size = function() {
        return binding.crypto_sign_BYTES;
    };

    /**
     * Set the default encoding to use in all string conversions
     * @param {String} encoding  encoding to use
     */
    self.setEncoding = function(encoding) {
        encoding.should.have.type('string').match(/^(?:utf8|ascii|binary|hex|utf16le|ucs2|base64)$/);
        self.defaultEncoding = encoding;
    };

    /**
     * Get the current default encoding
     * @returns {undefined|String}
     */
    self.getEncoding = function() {
        return self.defaultEncoding;
    };

    /**
     * Digitally sign message. This method creates an attached signature box
     * that embeds both message and public key.
     *
     * @param {Buffer|String|Array} message  message to sign
     * @param {String} [encoding]             encoding of message string
     *
     * @returns {Object}                       cipher box
     */
    self.sign = function (message, encoding) {
        encoding = String(encoding) || self.defaultEncoding || 'utf8';

        var buf = toBuffer(message, encoding);

        var signature = binding.crypto_sign(buf, self.iKey.sk().get());
        if( !signature ) {
            return undefined;
        }

        return {
            sign: signature,
            publicKey: self.iKey.pk().get()
        };
    };

    /**
     * Digitally sign message. This method creates a detached signature that
     * does not embed message or public key.
     *
     * @param {Buffer|String|Array} message  message to sign
     * @param {String} [encoding]            encoding of message string
     *
     * @returns {Buffer}                     detached signature for the message
     */
    self.signDetached = function(message, encoding) {
        encoding = String(encoding) || self.defaultEncoding || 'utf8';

        var buf = toBuffer(message, encoding);

        return binding.crypto_sign_detached(buf, self.iKey.sk().get());
    };
};

/**
 * Verify digital signature
 *
 * @param {Buffer|String|Array} cipherText  the signed message
 */
Sign.verify = function (signature) {
    signature.should.have.type('object').with.properties('sign', 'publicKey');
    return binding.crypto_sign_open(signature.sign, signature.publicKey);
};

/**
 * Verify detached digital signature.
 *
 * Remark, the `encoding` parameter will be used to decode all parameters that
 * are given as strings. If your parameters have different encodings you should
 * decode them before calling this method. But do note, that parameters
 * specified as buffers will not be decoded, regardless of the value of the
 * `encoding` parameter.
 *
 * @param {Buffer|String|Array} signature   signature to verify
 * @param {Buffer|String|Array} publicKey   public key for verification
 * @param {Buffer|String|Array} message     message to verify
 * @param {String} [encoding]               encoding of parameters that aren't buffers
 *
 * @returns {Boolean}                       true, if signature was valid
 */
Sign.verifyDetached = function(signature, publicKey, message, encoding) {
    encoding = String(encoding) || 'utf8';

    signature   = toBuffer(signature, encoding);
    publicKey   = toBuffer(publicKey, encoding);
    message     = toBuffer(message, encoding);

    return binding.crypto_sign_verify_detached(signature, message, publicKey);
};

module.exports = Sign;