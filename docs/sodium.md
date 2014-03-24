# General Use
The following objects are available in the `sodium` library

  * **api** - access to low level `libsodium` api
  * **Utils** - utility functions
  * **Hash** - all hash functions
  * **Random** - random number generator functions
  * **Box** - public key asymmetric crypto
  * **SecretKey** - symmetric key crypto 
  * **Stream** - stream crypto
  * **Sign** - signature generation and validation
  * **Auth** - authentication
  * **OneTimeAuth** - one time authentication
  * **Nonces** - nonce generation
  * **Key** - keys for all crypto functions


Lets generate a random number using by requiring the full `sodium` library

    var sodium = require('sodium');
    var n = sodium.api.randombytes_random();

Since we only need to call one method from the low level API we could require just the API functions like this:

    var lowLevelApi = require('sodium').api;
  	var n = lowlevelApi.randombytes_random();
  	
The same method can be applied to the other objects exposed through `sodium`.

The low level API gives you access to all ported `libsodium` functions directly. If you have experience using `libsodium` you can bypass the high-level APIs and use `libsodium` directly.
