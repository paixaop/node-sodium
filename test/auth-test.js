var test = require("tap").test

var sodium = require('../build/Release/sodium');
var Auth = require('../lib/auth');

test("Auth Test", function (t) {
        
        t.plan(1)
        var auth = new Auth();
        t.equal(auth.key().size(), sodium.crypto_auth_KEYBYTES, "Auth size is correct")
        t.end() 

});
