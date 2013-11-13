/**
 * Main module file
 *
 * @name node-sodium
 * @author bmf
 * @date 11/9/13
 */

// Base
var binding = require('../build/Release/sodium');
var toBuffer = require('./toBuffer');

// Public Key
var Box = require('./box');
var Sign = require('./sign');

// Symmetric Key  
var SecretBox = require('./secretbox');
var Auth = require('./auth');
var OneTimeAuth = require('./onetime-auth');
var Stream = require('./stream');

// Nonces
var BoxNonce = require('./nonces/box-nonce');
var SecretBoxNonce = require('./nonces/secretbox-nonce');
var StreamNonce = require('./nonces/stream-nonce');

// Keys
var AuthKey = require('./keys/auth-key');
var BoxKey = require('./keys/box-key');
var KeyPair = require('./keys/keypair');
var OneTimeKey = require('./keys/onetime-key');
var SecretBoxKey = require('./keys/secretbox-key');
var SignKey = require('./keys/sign-key');
var StreamKey = require('./keys/stream-key');

/**
 *  Export all low level lib sodium functions directly
 *  for developers that are used to lib sodium C interface
 */
module.exports.api = binding;

module.exports.version = binding.version;
module.exports.versionMinor = binding.versionMinor;
module.exports.versionMajor = binding.versionMajor;

/** Utilities */
module.exports.Utils = { };
module.exports.Utils.memzero = binding.memzero;
module.exports.Utils.verify16 = binding.crypto_verify_16;
module.exports.Utils.verify32 = binding.crypto_verify_32;
module.exports.Utils.toBuffer = toBuffer;

/** Hash functions */
module.exports.Hash = {

    /** Default message hash */
    hash: binding.crypto_hash,

    /** SHA 256 */
    sha256: binding.crypto_hash_sha256,

    /** SHA 512 */
    sha512: binding.crypto_hash_sha512
};

/** Random Functions */
module.exports.Random = {

    /** Fill buffer with random bytest */
    buffer : binding.randombytes_buf,

    /** Initialize OS dependent random device */
    stir : binding.randombytes_stir,

    /** Close the ranom device */
    close : binding.randombytes_close,

    /** Return a random 32-bit unsigned value */
    rand : binding.randombytes_random,

    /** Return a value between 0 and upper_bound using a uniform distribution */
    uniform : binding.randombytes_uniform
};

// Public Key
module.exports.Box = Box;
module.exports.Sign = Sign;

// Symmetric Key
module.exports.Auth = Auth;
module.exports.SecretBox = SecretBox;
module.exports.Stream = Stream;
module.exports.OneTimeAuth = OneTimeAuth;

// Nonces
module.exports.Nonces = {
    Box: BoxNonce,
    SecretBox: SecretBoxNonce,
    Stream: StreamNonce
};

// Symmetric Keys
module.exports.Key = {
    SecretBox: SecretBoxKey,
    Auth: AuthKey,
    OneTimeAuth: OneTimeKey,
    Stream: StreamKey,

    // Public/Secret Key Pairs
    Box: BoxKey,
    Sign: SignKey
};
/**
 * Lib Sodium Constants
 *
 * the base library defines several important constant that you should use to
 * check the size of buffers, nonces, keys, etc.
 *
 * All constants represent the size of the buffer or zone of a buffer in bytes
 */
module.exports.Const = {};

/** Box related constant sizes in bytes */
module.exports.Const.Box = {
    
    /** Box Nonce buffer size in bytes */
    nonceBytes : binding.crypto_box_NONCEBYTES,
    
    /** Box Public Key buffer size in bytes */
    publicKeyBytes : binding.crypto_box_PUBLICKEYBYTES,
    
    /** Box Public Key buffer size in bytes */
    secretKeyBytes : binding.crypto_box_SECRETKEYBYTES,
    
    /**
     * Messages passed to low level API should be padded with zeroBytes at the beginning.
     * This implementation automatically pads the message, so no need to do it on your own
     */
    zeroBytes : binding.crypto_box_ZEROBYTES,
    
    /**
     * Encrypted messages are padded with zeroBoxSize bytes of zeros. If the padding is not
     * there the message will not decrypt succesfuly.
     */
    boxZeroBytes : binding.crypto_box_BOXZEROBYTES,
    
    /**
     * Padding used in beforenm method. Like zeroBytes this implementation automatically
     * pads the message.
     *
     * @see Const.Box.zeroBytes
     */
    beforenmBytes : binding.crypto_box_BEFORENMBYTES
};

/** Authentication Constants */
module.exports.Const.Auth = {
    
    /** Size of the authentication token */
    bytes: binding.crypto_auth_BYTES,

    /** Size of the secret key used to generate the authentication token */
    keyBytes: binding.crypto_auth_KEYBYTES
};

/** One Time Authentication Constants */
module.exports.Const.OneTimeAuth = {

    /** Size of the authentication token */
    bytes: binding.crypto_auth_BYTES,
    
    /** Size of the secret key used to generate the authentication token */
    keyBytes: binding.crypto_auth_KEYBYTES
};

/** SecretBox Symmetric Key Crypto Constants */
module.exports.Const.SecretBox = {

    /** SecretBox padding of cipher text buffer */
    boxZeroBytes: binding.crypto_secretbox_BOXZEROBYTES,
    
    /** Size of the secret key used to encrypt/decrypt messages */
    keyBytes: binding.crypto_secretbox_KEYBYTES,
    
    /** Size of the Nonce used in encryption/decryption of messages */
    nonceBytes: binding.crypto_secretbox_NONCEBYTES,
    
    /** Passing of message. This implementation does message padding automatically */
    zeroBytes: binding.crypto_secretbox_ZEROBYTES
};

/** Digital message signature constants */
module.exports.Const.Sign = {

    /** Size of the generated message signature */
    bytes: binding.crypto_sign_BYTES,

    /** Size of the public key used to verify signatures */
    publicKeyBytes: binding.crypto_sign_PUBLICKEYBYTES,

    /** Size of the secret key used to sign a message */
    secretKeyBytes: binding.crypto_sign_SECRETKEYBYTES
};

/** Symmetric Encryption Constans */
module.exports.Const.Stream = {
    /** Size of secret key used to encrypt/decrypt messages */
    keyBytes : binding.crypto_stream_KEYBYTES,

    /** Size of nonce used to encrypt/decrypt messages */
    nonceBytes : binding.crypto_stream_NONCEBYTES
};