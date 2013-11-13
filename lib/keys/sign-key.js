/**
 * Created by bmf on 11/2/13.
 */
var util = require('util');
var binding = require('../../build/Release/sodium');
var KeyPair = require('./keypair');

var Sign = function SignKey(publicKey, secretKey, encoding) {
    var self = this;

    KeyPair.call(this);

    self.init({
        publicKeySize: binding.crypto_sign_PUBLICKEYBYTES,
        secretKeySize: binding.crypto_sign_SECRETKEYBYTES,
        publicKey: publicKey,
        secretKey: secretKey,
        encoding: encoding,
        type: 'SignKey'
    });

    self.generate = function() {
        var keys = binding.crypto_sign_keypair();
        self.secretKey.set(keys.secretKey);
        self.publicKey.set(keys.publicKey);
    };

    if( !publicKey || !secretKey ||
        !self.isValid({ 'publicKey': publicKey, 'secretKey': secretKey }) ) {

        // Generate the keys
        self.generate();
    }
};
util.inherits(Sign, KeyPair);
module.exports = Sign;