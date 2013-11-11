/**
 * Main module file
 *
 * @name node-sodium
 * @author bmf
 * @date 11/9/13
 */
var binding = require('../build/Release/sodium');
var toBuffer = require('./toBuffer');

var Box = require('./box');
var SecretBox = require('./secretbox');
var Auth = require('./auth');
var CryptoBaseBuffer = require('./crypto-base-buffer');
var BoxNonce = require('./nonces/box-nonce');
var SecretBoxNonce = require('./nonces/secretbox-nonce');
var StreamNonce = require('./nonces/stream-nonce');
var AuthKey = require('./keys/auth-key');
var BoxKey = require('./keys/box-key');
var KeyPair = require('./keys/keypair');
var OneTimeKey = require('./keys/onetime-key');
var SecretBoxKey = require('./keys/secretbox-key');
var SignKey = require('./keys/sign-key');
var StreamKey = require('./keys/stream-key');


module.exports.version = binding.version;
module.exports.versionMinor = binding.versionMinor;
module.exports.versionMajor = binding.versionMajor;


module.exports.Utils = { };
module.exports.Utils.memzero = binding.memzero;
module.exports.Utils.verify16 = binding.crypto_verify_16;
module.exports.Utils.verify32 = binding.crypto_verify_32;
module.exports.Utils.toBuffer = toBuffer;

module.exports.Hash = { };
module.exports.Hash.sha256 = binding.crypto_hash_sha256;
module.exports.Hash.sha512 = binding.crypto_hash_sha512;


// Random Functions
module.exports.Random = { };
module.exports.Random.buffer = binding.randombytes_buf;
module.exports.Random.stir = binding.randombytes_stir;
module.exports.Random.close = binding.randombytes_close;
module.exports.Random.rand = binding.randombytes_random;
module.exports.Random.uniform = binding.randombytes_uniform;

// High Level APIs
module.exports.Auth = Auth;
module.exports.Box = Box;
module.exports.SecretBox = SecretBox;

module.exports.Nonces = {};
module.exports.Nonces.Box = BoxNonce;
module.exports.Nonces.SecretBox = SecretBoxNonce;
module.exports.Nonces.Stream = StreamNonce;

module.exports.Key = {};
module.exports.Key.SecretBox = SecretBoxKey;
module.exports.Key.Auth = AuthKey;
module.exports.Key.OneTime = OneTimeKey;
module.exports.Key.Stream = StreamKey;

module.exports.KeyPair = {};
module.exports.KeyPair.Box = BoxKey;
module.exports.KeyPair.Sign = SignKey;
