var assert = require('assert');
var sodium = require('../build/Release/sodium');


var expected = [
    "24f950aac7b9ea9b3cb728228a0c82b67c39e96b4b344798870d5daee93e3ae5931baae8c7cacfea4b629452c38026a81d138bc7aad1af3ef7bfd5ec646d6c28",
    "a77abe1ccf8f5497e228fbc0acd73a521ededb21b89726684a6ebbc3baa32361aca5a244daa84f24bf19c68baf78e6907625a659b15479eb7bd426fc62aafa73",
    "12a61f4e173fb3a11c05d6471f74728f76231b4a5fcd9667cef3af87a3ae4dc2",
    "71cc8123fef8c236e451d3c3ddf1adae9aa6cd9521e7041769d737024900a03a",
];

var x = Buffer.from("testing\n");
var x2 = Buffer.from(
    "The Conscience of a Hacker is a small essay written January 8, 1986 by a " +
    "computer security hacker who went by the handle of The Mentor, who " +
    "belonged to the 2nd generation of Legion of Doom.");

describe("libsodium_hash", function () {
    it('crypto_hash', function() {
        var h = sodium.crypto_hash(x);
        assert(h.equals(Buffer.from(expected[0], 'hex')));

        h = sodium.crypto_hash(x2);
        assert(h.equals(Buffer.from(expected[1], 'hex')));
        
        h = sodium.crypto_hash_sha256(x);
        assert(h.equals(Buffer.from(expected[2], 'hex')));
        
        h = sodium.crypto_hash_sha256(x2);
        assert(h.equals(Buffer.from(expected[3], 'hex')));

        assert(sodium.crypto_hash_bytes() > 0);
        assert(sodium.crypto_hash_primitive() === "sha512");
        assert(sodium.crypto_hash_sha256_bytes() > 0);
        assert(sodium.crypto_hash_sha512_bytes() >= sodium.crypto_hash_sha256_bytes());
        assert(sodium.crypto_hash_sha512_bytes() == sodium.crypto_hash_bytes());
        assert(sodium.crypto_hash_sha256_statebytes() > 0);
        assert(sodium.crypto_hash_sha512_statebytes() > 0);
    });
});

