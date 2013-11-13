/**
 * Created by bmf on 11/2/13.
 */
var binding = require('../../build/Release/sodium');
var should = require('should');
var CryptoBaseBuffer = require('../crypto-base-buffer');

module.exports = function KeyPair() {
    var self = this;

    /** secret key */
    self.secretKey = new CryptoBaseBuffer();

    /** public key */
    self.publicKey = new CryptoBaseBuffer();

    self.type = undefined;

    /** default encoding to use in all string operations */
    self.defaultEncoding = undefined;

    self.init = function(options) {
        options = options || {};

        // We will only accept hex string representations of keys
        self.publicKey.setValidEncodings(['hex', 'base64']);
        self.secretKey.setValidEncodings(['hex', 'base64']);

        // the default encoding to us in all string set/toString methods is Hex
        self.publicKey.setEncoding('base64');
        self.secretKey.setEncoding('base64');

        if( !options.type ) {
            throw new Error('[KeyPair] type not given in init');
        }

        self.type = options.type;

        // Public Key
        if( options.publicKey instanceof KeyPair ) {
            self.publicKey = options.publicKey.pk();
        }
        else if( options.publicKey instanceof CryptoBaseBuffer ) {
            self.publicKey = options.publicKey;
        }
        else {
            self.publicKey.init({
                expectedSize: options.publicKeySize,
                value: options.publicKey,
                encoding: options.encoding,
                type: options.type + 'PublicKey'
            });
        }

        // Secret Key
        if( options.secretKey instanceof KeyPair ) {
            self.secretKey = options.secretKey.sk();
        }
        else if( options.secretKey instanceof CryptoBaseBuffer ) {
            self.secretKey = options.secretKey;
        }
        else {
            self.secretKey.init({
                expectedSize: options.secretKeySize,
                value: options.secretKey,
                encoding: options.encoding,
                type: options.type + 'SecretKey'
            });
        }
    };

    /**
     * Set the default encoding to use in all string conversions
     * @param {String} encoding  encoding to use
     */
    self.setEncoding = function(encoding) {
        encoding.should.have.type('string').match(/^(?:utf8|ascii|binary|hex|utf16le|ucs2|base64)$/);
        self.defaultEncoding = encoding;
        self.publicKey.setEncoding(encoding);
        self.secretKey.setEncoding(encoding);
    }

    /**
     * Get the current default encoding
     * @returns {undefined|String}
     */
    self.getEncoding = function() {
        return self.defaultEncoding;
    }

    /**
     * Check if key pair is valid
     * @param keys {Object} an object with secrteKey, and publicKey members
     * @returns {boolean} true is both public and secret keys are valid
     */
    self.isValid = function(keys, encoding) {
        keys.should.have.type('object');
        keys.should.have.properties('publicKey', 'secretKey');

        encoding = encoding || self.defaultEncoding;

        return self.publicKey.isValid(keys.publicKey, encoding) &&
               self.secretKey.isValid(keys.secretKey, encoding);
    };

    /**
     * Wipe keys securely
     */
    self.wipe = function() {
        self.publicKey.wipe();
        self.secretKey.wipe();
    };

    /**
     * Generate a random key pair
     */
    self.generate = function() {
        throw new Error("KeyPair: this method should be implemented in each sub class");
    };

    /**
     *  Getter for the public key
     * @returns {undefined| Buffer} public key
     */
    self.getPublicKey = function() {
        return self.publicKey;
    };

    /**
     *  Getter for the secretKey
     * @returns {undefined| Buffer} secret key
     */
    self.getSecretKey = function() {
        return self.secretKey;
    };

    self.pk = self.getPublicKey;
    self.sk = self.getSecretKey;


    /**
     *  Getter for the key pair
     * @returns {Object} with both public and private keys
     */
    self.get = function() {
        return {
            'publicKey' : self.publicKey.get(),
            'secretKey' : self.secretKey.get()
        };
    };

    /**
     * Set the secret key to a known value
     * @param v {String|Buffer|Array} the secret key
     * @param encoding {String} optional. If v is a string you can specify the encoding
     */
    self.set = function(keys, encoding) {
        keys.should.have.type('object');

        if( keys instanceof KeyPair ) {
            self.secretKey.set(keys.sk(), encoding);
            self.publicKey.set(keys.pk(), encoding);
        }
        else {
            encoding = encoding || self.defaultEncoding;
            if( typeof keys === 'object' ) {
                if( keys.secretKey ) {
                    self.secretKey.set(keys.secretKey, encoding);
                }
                if( keys.publicKey ) {
                    self.publicKey.set(keys.publicKey, encoding);
                }
            }
        }
    };

    self.setPublicKey = function(key, encoding) {
        if( key instanceof KeyPair ) {
            self.publicKey = key.pk();
        }
        else if( key instanceof CryptoBaseBuffer ) {
            if( key.length = self.expectedSize)
            self.publicKey = key;

        }
    }

    self.setSecretKey = function(key, encoding) {

    }


    /**
     * Convert the secret key to a string object
     * @param encoding {String} optional sting encoding. defaults to 'hex'
     */
    self.toString = function(encoding) {
        encoding = encoding || self.defaultEncoding;

        return self.secretKey.toString(encoding) + "," +
               self.publicKey.toString(encoding);
    };

    /**
     * Convert the secret key to a JSON object
     * @param encoding {String} optional sting encoding. defaults to 'hex'
     */
    self.toJson = function(encoding) {
        encoding = encoding || self.defaultEncoding;

        var out = '{';
        if( self.secretKey ) {
            out += '"secretKey" :"' + self.secretKey.toString(encoding) + '"';
        }
        if( self.secretKey && self.publicKey ) {
            out += ', ';
        }
        if( self.publicKey ) {
            out += '"publicKey" :"' + self.publicKey.toString(encoding) + '"';
        }
        out += '}';
        return out;
    };
};
