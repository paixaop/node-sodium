# node-sodium


Port of the [lib sodium](https://github.com/jedisct1/libsodium) Encryption Library to Node.js.

This a work in progress but most of Lib Sodium as been ported already. Missing are the `afternm` and `beforenm` functions.

There's a "low level" native module that gives you access directly to Lib Sodium, and a friendlier high level API that makes the use of the library a bit easier.

# Lib Sodium Documentation
Lib Sodium is somewhat documented [here](http://mob5.host.cs.st-andrews.ac.uk/html/). Node-Sodium follows the same structure and I will keep documenting it as fast as possible. 

# Install
Clone the git repository, then and change to the local directory where you ran git clone to, then you need to compile Lib Sodium it self

    cd libsodium
    ./autogen
    ./configure
    make

Build node-sodium native module

    cd ..
    npm build .
    npm install
    

# Testing
You need to have mocha test suite installs then you can run the node-sodium unit tests by

    make test
    
# Coverage Reports
	
	make test-cov
	
# Usage

Just a quick example that uses the same public/secret key pair to encrypt and then decrypt the message.

    var sodium = require('sodium');        
    var box = new sodium.Box();     // random key pair generated automatically
    
    var cipherText = box.encrypt("This is a secret message", "utf8");
    var plainText = box.decrypt(cipherText);
    


