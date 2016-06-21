[![Build Status](https://secure.travis-ci.org/paixaop/node-sodium.png)](http://travis-ci.org/paixaop/node-sodium)

# node-sodium

Uses Libsodium 1.0.10

Port of the [lib sodium](https://github.com/jedisct1/libsodium) Encryption Library to Node.js.

As of libsodium 1.0.10 all functions except memory allocation have been implemented.
Missing functions are listed in [`docs/not implemented.md`](https://github.com/paixaop/node-sodium/blob/master/docs/not%20implemented.md).


There's a "low level" native module that gives you access directly to Lib Sodium, and a friendlier high level API that makes the library a bit easier to use.

Check [`docs/low-level-api.md`](https://github.com/paixaop/node-sodium/tree/master/docs/low-level-api.md) for a list of all lib sodium functions included in node-sodium.

# Usage

Just a quick example that uses the same public/secret key pair to encrypt and then decrypt the message.

    var sodium = require('sodium');        
    var box = new sodium.Box();     // random key pair, and nonce generated automatically
    
    var cipherText = box.encrypt("This is a secret message", "utf8");
    var plainText = box.decrypt(cipherText);
    
    
# Low Level API
A low level API is provided for advanced users. The functions available through the low level API have the exact same names as in lib sodium, and are available via the `sodium.api` object. Here is one example of how to use some of the low level API functions to encrypt/decrypt a message:

    var sodium = require('sodium').api;
    
    // Generate keys
    var sender = sodium.crypto_box_keypair();
    var receiver = sodium.crypto_box_keypair();
    
    // Generate random nonce
    var nonce = new Buffer(sodium.crypto_box_NONCEBYTES);
    sodium.randombytes_buf(nonce);
    
    // Encrypt
    var plainText = new Buffer('this is a message');
    var cipherMsg = sodium.crypto_box(plainText, nonce, receiver.publicKey, sender.secretKey);

    // Decrypt
    var plainBuffer = sodium.crypto_box_open(cipherMsg,nonce,sender.publicKey, receiver.secretKey);

    // We should get the same plainText!
    if (plainBuffer.toString() == plainText) {
        console.log("Message decrypted correctly");
    }
    
As you can see the high level API implementation is easier to use, but the low level API will feel just right for those experienced with the C version of lib sodium. It also allows you to bypass any bugs in the high level APIs.

You can find this code sample in `examples\low-level-api.js`.
    
# Documentation
Please read the work in progress documentation found under [`docs/`](https://github.com/paixaop/node-sodium/tree/master/docs).

You should also review the unit tests as most of the high level API is "documented" there.
Don't forget to check out the [examples](https://github.com/paixaop/node-sodium/tree/master/examples) as well.

The low level `libsodium` API documentation is now complete. All ported functions have been documented in [low-level-api.md](./docs/low-level-api.md) with code examples.

Please be patient as I document the rest of the APIs, or better still: help out! :)

# Lib Sodium Documentation
Lib Sodium is documented [here](http://doc.libsodium.org/). Node-Sodium follows the same structure and I will keep documenting it as fast as possible. 

# Install

Tested on Mac, Linux and IllumOS Systems

    npm install sodium
    
node-sodium depends on libsodium, so if libsodium does not compile on your platform chances are `npm install sodium` will fail.

Installation will fail if `node-gyp`is not installed on your system. Please run

    npm install node-gyp -g
    
Before you install `node-sodium`. If you run into permission errors while installing `node-gyp` run as Adminstrator on Windows or use `sudo` in other OSes.

	sudo npm install node-gyp -g

# Manual Build

Node Sodium includes the source of libsodium, so the normal install will try to compile libsodium directly from source, using libsodium's own build tools.
This is the prefered method of compiling node sodium.
If you can't compile libsodium from source in your platform you can [download a pre-compiled binary](http://www.libsodium.org/releases) and copy it to the `./deps/build/lib` folder.

Before you run the manual build you must run the `npm install` once to install the required dependencies, like `node-gyp` that are needed to compile `node-sodium`.
Please note that `npm install` will install the dependencies and compile `node-sodium` as well. After this initial step you can make changes to the source and run the following commands to manually build the module:

    make sodium

## Building on Windows

`npm install sodium` might fail in Windows, as the initial build will most
likely not succeed. In that case, clone this repository and run npm install to
install dependencies; then copy the pre-compiled binary data (cf. above) into
the following directories:

* The contents of `include/` to `deps/build/include/`
(`deps/build/include/sodium.h` must exist)
* The contents of `x64/Release/v120/dynamic/` to `./deps/build/lib/`
(`deps/build/lib/libsodium.lib` must exist)

Afterwards, `make sodium` (or manual `node-gyp rebuild`) should work normally.
`--msvs_version=2013` may need to be configured for node-gyp, too, but this is
currently unverified.

Note that static compilation is not supported currently, so `libsodium.dll`
**must** be distributed along with your code.

# SECURITY WARNING: Using a Binary Static libsodium

Node Sodium is a strong encryption library, odds are that a lot of security functions of your application depend on it, so *DO NOT* use binary libsodium distributions that you haven't verified.
If you use a pre-compiled version of libsodium you MUST be sure that nothing mallicious was added to the compiled version you are using.

# Code Samples
Please check the fully documented code samples in `test/test_sodium.js`.

# Installing Mocha Test Suite

To run the unit tests you need Mocha. If you'd like to run coverage reports you need mocha-istanbul. You can install both globally by doing

    npm install -g mocha mocha-istanbul

You may need to run it with `sudo` as only the root user has access to Node.js global directories

    sudo npm install -g mocha mocha-istanbul

# Unit Tests
You need to have mocha test suite installed globally then you can run the node-sodium unit tests by

    make test
    
# Coverage Reports
You need to have mocha and mocha-istanbul installed globally then you can run the node-sodium coverage reports by
	
    make test-cov
	

# License
This software is licensed through the MIT License. Please read the LICENSE file for more details.

# Author

Built and maintained by Pedro Paixao
