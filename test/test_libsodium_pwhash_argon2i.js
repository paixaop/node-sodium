var assert = require('assert');
var sodium = require('../build/Release/sodium');

var OPSLIMIT = 3
var MEMLIMIT = 5000000;

describe("libsodium_pwhash_argon2i", function () {
    it("Test Vectors 1 - crypto_pwhash", function() {
        var tests = [
            [ "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae0" +
              "65577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d" +
              "a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f5" +
              "8d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6",
              127,
              "5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2",
              155, 5, 7256678, 1 ],
            [ "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed" + 
              "9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e0" +
              "0cc2890277f0fd3c622115772f7048adaebed86e",
              86,
              "f1192dd5dc2368b9cd421338b22433455ee0a3699f9379a08b9650ea2c126f0d",
              250, 4, 7849083, 1 ],
            [ "92263cbf6ac376499f68a4289d3bb59e5a22335eba63a32e6410249155b956b6a3" +
              "b48d4a44906b18b897127300b375b8f834f1ceffc70880a885f47c33876717e392" +
              "be57f7da3ae58da4fd1f43daa7e44bb82d3717af4319349c24cd31e46d295856b0" +
              "441b6b289992a11ced1cc3bf3011604590244a3eb737ff221129215e4e4347f491" +
              "5d41292b5173d196eb9add693be5319fdadc242906178bb6c0286c9b6ca6012746" +
              "711f58c8c392016b2fdfc09c64f0f6b6ab7b",
              183,
              "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194",
              249, 3, 7994791, 1 ],
            [ "027b6d8e8c8c474e9b69c7d9ed4f9971e8e1ce2f6ba95048414c3970f0f09b70e3" +
              "b6c5ae05872b3d8678705b7d381829c351a5a9c88c233569b35d6b0b809df44b64" +
              "51a9c273f1150e2ef8a0b5437eb701e373474cd44b97ef0248ebce2ca0400e1b53" +
              "f3d86221eca3f18eb45b702b9172440f774a82cbf1f6f525df30a6e293c873cce6" +
              "9bb078ed1f0d31e7f9b8062409f37f19f8550aae",
              152,
              "eb2a3056a09ad2d7d7f975bcd707598f24cd32518cde3069f2e403b34bfee8a5", 5,
              4, 1397645, 1 ],
            [ "4a857e2ee8aa9b6056f2424e84d24a72473378906ee04a46cb05311502d5250b82" +
              "ad86b83c8f20a23dbb74f6da60b0b6ecffd67134d45946ac8ebfb3064294bc097d" +
              "43ced68642bfb8bbbdd0f50b30118f5e",
              82,
              "39d82eef32010b8b79cc5ba88ed539fbaba741100f2edbeca7cc171ffeabf258",
              190, 3, 1432947, 1 ],
            [ "c7b09aec680e7b42fedd7fc792e78b2f6c1bea8f4a884320b648f81e8cf515e8ba" +
              "9dcfb11d43c4aae114c1734aa69ca82d44998365db9c93744fa28b63fd16000e82" +
              "61cbbe083e7e2da1e5f696bde0834fe53146d7e0e35e7de9920d041f5a5621aabe" +
              "02da3e2b09b405b77937efef3197bd5772e41fdb73fb5294478e45208063b5f58e" +
              "089dbeb6d6342a909c1307b3fff5fe2cf4da56bdae50848f",
              156,
              "039c056d933b475032777edbaffac50f143f64c123329ed9cf59e3b65d3f43b6",
              178, 3, 4886999, 1 ],
            [ "b540beb016a5366524d4605156493f9874514a5aa58818cd0c6dfffaa9e90205f1" +
              "7b",
              34,
              "44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb",
              231, 1, 1631659, 1 ],
            [ "a14975c26c088755a8b715ff2528d647cd343987fcf4aa25e7194a8417fb2b4b3f" +
              "7268da9f3182b4cfb22d138b2749d673a47ecc7525dd15a0a3c66046971784bb63" +
              "d7eae24cc84f2631712075a10e10a96b0e0ee67c43e01c423cb9c44e5371017e9c" +
              "496956b632158da3fe12addecb88912e6759bc37f9af2f45af72c5cae3b179ffb6" +
              "76a697de6ebe45cd4c16d4a9d642d29ddc0186a0a48cb6cd62bfc3dd229d313b30" +
              "1560971e740e2cf1f99a9a090a5b283f35475057e96d7064e2e0fc81984591068d" +
              "55a3b4169f22cccb0745a2689407ea1901a0a766eb99",
              220,
              "3d968b2752b8838431165059319f3ff8910b7b8ecb54ea01d3f54769e9d98daf",
              167, 3, 1784128, 1 ],
			  [ 
				"a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae0" +
				"65577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d" +
				"a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f5" +
				"8d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6",
				127,
				"5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2",
				155, 4, 397645, 1 
			],
			[ 
				"a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae0" +
				"65577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d" +
				"a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f5" +
				"8d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6",
				127,
				"5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2",
				155, 3, 397645, 1 
			],
        ];

        var expected = [
          	"23b803c84eaa25f4b44634cc1e5e37792c53fcd9b1eb20f865329c68e09cbfa9f196875" +
			"7901b383fce221afe27713f97914a041395bbe1fb70e079e5bed2c7145b1f6154046f59" + 
			"58e9b1b29055454e264d1f2231c316f26be2e3738e83a80315e9a0951ce4b137b52e7d5" +
			"ee7b37f7d936dcee51362bcf792595e3c896ad5042734fc90c92cae572ce63ff659a2f7" +
			"974a3bd730d04d525d253ccc38",
          	"0bb3769b064b9c43a9460476ab38c4a9a2470d55d4c992c6e723af895e4c07c09af41f2" +
			"2f90eab583a0c362d177f4677f212482fd145bfb9ac6211635e48461122bb49097b5fb0" + 
			"739d2cd22a39bf03d268e7495d4fd8d710aa156202f0a06e932ff513e6e7c76a4e98b6d" +
			"f5cf922f124791b1076ad904e6897271f5d7d24c5929e2a3b836d0f2f2697c2d758ee79" +
			"bf1264f3fae65f3744e0f6d7d07ef6e8b35b70c0f88e9036325bfb24ac7f550351486da" +
			"87aef10d6b0cb77d1cf6e31cf98399c6f241c605c6530dffb4764784f6c0b0bf601d4e4" +
			"431e8b18dabdc3079c6e264302ade79f61cbd5497c95486340bb891a737223100be0429" +
			"650",
          	"e9aa073b0b872f15c083d1d7ce52c09f493b827ca78f13a06c1721b45b1e17b24c04e19" +
			"fe869333135360197a7eb55994fee3e8d9680aedfdf7674f3ad7b84d59d7eab03579ffc" + 
			"10c7093093bc48ec84252aa1b30f40f5e838f1443e15e2772a39f4e774eb052097e8881" +
			"e94f15457b779fa2af2bbc9a993687657c7704ac8a37c25c1df4289eb4c70da45f2fd46" +
			"bc0f78259767d3dd478a7c369cf866758bc36d9bd8e2e3c9fb0cf7fd6073ebf630c1f67" +
			"fa7d303c07da40b36749d157ea37965fef810f2ea05ae6fc7d96a8f3470d73e15b22b42" +
			"e8d6986dbfe5303256b2b3560372c4452ffb2a04fb7c6691489f70cb46831be0679117f7",
          	"",
          	"c121209f0ba70aed93d49200e5dc82cce013cef25ea31e160bf8db3cf448a59d1a56f6c" +
			"19259e18ea020553cb75781761d112b2d949a297584c65e60df95ad89c4109825a3171d" +
			"c6f20b1fd6b0cdfd194861bc2b414295bee5c6c52619e544abce7d520659c3d51de2c60" + 
			"e89948d830695ab38dcb75dd7ab06a4770dd4bc7c8f335519e04b038416b1a7dbd25c02" +
			"6786a8105c5ffe7a0931364f0376ae5772be39b51d91d3281464e0f3a128e7155a68e87" +
			"cf79626ffca0b2a3022fc8420",
          	"91c337ce8918a5805a59b00bd1819d3eb4356807cbd2a80b271c4b482dce03f5b02ae4e" +
			"b831ff668cbb327b93c300b41da4852e5547bea8342d518dd9311aaeb5f90eccf66d548" + 
			"f9275631f0b1fd4b299cec5d2e86a59e55dc7b3afab6204447b21d1ef1da824abaf31a2" + 
			"5a0d6135c4fe81d34a06816c8a6eab19141f5687108500f3719a862af8c5fee36e130c6" +
			"9921e11ce83dfc72c5ec3b862c1bccc5fd63ad57f432fbcca6f9e18d5a59015950cdf053",
          	"",
          	"e942951dfbc2d508294b10f9e97b47d0cd04e668a043cb95679cc1139df7c27cd543676" +
			"88725be9d069f5704c12223e7e4ca181fbd0bed18bb4634795e545a6c04a7306933a41a" +
			"794baedbb628d41bc285e0b9084055ae136f6b63624c874f5a1e1d8be7b0b7227a171d2" + 
			"d7ed578d88bfdcf18323198962d0dcad4126fd3f21adeb1e11d66252ea0c58c91696e91" +
			"031bfdcc2a9dc0e028d17b9705ba2d7bcdcd1e3ba75b4b1fea",
		  	"fd329873387429cb79faaec4f65c35649f65de0aabc1f092ca9dee20029d8ae6c3a97e9" +
			"940763e1703a7fef5a20eb7f210123fc8c6d3f1745d19d5e3c1eb392ab4a6070c8a6b9e" +
			"cbeabae0711326e81530099541a882d4bd7733c4a7477ae72b6928c46cd07264172a9d2" +
			"cfb7d649594f877f8b447d9c01b17996b85db5a71f733f8cc5fd0436540a5b7a1d79de0" + 
			"9e20c3abe6515501b3156cd51e",
			"bbbc4c7963593601d4d685ed9d89682374f8e6b3ce92ce8ccc702728ec8bf839fd7cb8e" + 
			"37ddb09be8c18c7e0ed099949665227a00fb33e1f63ca830dbeb13b29d987b445b3e081" +
			"cd8428bdb2f9e003e12bea98230fd30842fa193af9169171b550322072c88330ea464cb" +
			"e02b6ee044374d3f3d174c23617b707159a11926c56601123dcc30508ec84fdb0797b7a" +
			"b23a77eeefb2a0be2ef45e903c"
        ];

        for(var i  = 0; i < tests.length; i++) {
            var passwd = Buffer.from(tests[i][0], 'hex');
            var passwd_len = tests[i][1];
            var salt = Buffer.from(tests[i][2], 'hex').slice(0, sodium.crypto_pwhash_saltbytes());
            var outlen = tests[i][3];
            var opslimit  = tests[i][4];
            var memlimit = tests[i][5];
            var lanes = tests[i][6];
            var alg = sodium.crypto_pwhash_alg_argon2i13();
    
            var out = sodium.crypto_pwhash(
                outlen, passwd,  salt, opslimit, memlimit, alg
            );
            var exp = Buffer.from(expected[i], 'hex');
            if( !out ) {
              assert(expected[i] === "", "Test vector " + i);
            }
            else {
              assert(out.equals(exp), "Test vector " + i);
            }
        }
    });

    it('Test Vectors 2 - crypto_pwhash', function() {
		var outLen = 256;
		var passwd = Buffer.from("password");
		var salt_hex = "5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2";
		var salt = Buffer.from(salt_hex, 'hex').slice(0, sodium.crypto_pwhash_saltbytes());

		var out = sodium.crypto_pwhash(outLen, passwd, salt, 3, 1 << 12, 0);
		assert(out === null);

		out = sodium.crypto_pwhash_argon2i(outLen, passwd, salt, 3, 1 << 12, 0);
		assert(out === null);
		 
		var out = sodium.crypto_pwhash(outLen, passwd, salt, 3, 1,
			sodium.crypto_pwhash_alg_argon2i13());
		assert(out === null);

		var out = sodium.crypto_pwhash(outLen, passwd, salt, 3, 1 << 12,
			sodium.crypto_pwhash_alg_argon2i13());
		assert(out === null);
		
		var out = sodium.crypto_pwhash(outLen, passwd, salt, 2, 1 << 12,
			sodium.crypto_pwhash_alg_argon2i13());
		assert(out === null);
		
		var out = sodium.crypto_pwhash(15, passwd, salt, 3, 1 << 12,
			sodium.crypto_pwhash_alg_argon2i13());
		assert(out === null);

		out = sodium.crypto_pwhash_argon2i(outLen, passwd, salt, OPSLIMIT, MEMLIMIT, 
			sodium.crypto_pwhash_alg_argon2id13());
		assert(out === null);

	});

	it('Test Vectors 3 - crypto_pwhash', function() {
		var tests = [
			[ "",
			  "$argon2i$v=19$m=4096,t=1,p=1$X1NhbHQAAAAAAAAAAAAAAA$bWh++" +
			  "MKN1OiFHKgIWTLvIi1iHicmHH7+Fv3K88ifFfI" 
			],
			[ "",
			  "$argon2i$v=19$m=2048,t=4,p=1$SWkxaUhpY21ISDcrRnYzSw$Mbg/" +
			  "Eck1kpZir5T9io7C64cpffdTBaORgyriLQFgQj8" 
			],
			[ "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg ",
			  "$argon2i$v=19$m=4096,t=3,p=2$X1NhbHQAAAAAAAAAAAAAAA$z/QMiU4lQxGsYNc/" +
			  "+K/bizwsA1P11UG2dj/7+aILJ4I" ],
			[ "K3S=KyH#)36_?]LxeR8QNKw6X=gFbxai$C%29V*",
			  "$argon2i$v=19$m=4096,t=3,p=1$X1NhbHQAAAAAAAAAAAAAAA$fu2Wsecyt+" +
			  "yPnBvSvYN16oP5ozRmkp0ixJ1YL19V3Uo" ]
		];

		for(var i  = 0; i < tests.length; i++) {
            var passwd = Buffer.from(tests[i][0], 'ascii');
            var out = Buffer.from(tests[i][1], 'ascii');
			var hash = Buffer.alloc(sodium.crypto_pwhash_strbytes()).fill(0);
			out.copy(hash, 0);
            var valid = sodium.crypto_pwhash_str_verify(hash, passwd);
            assert(valid);
        }
	});
});

describe("libsodium_pwhash_argon2i str tests", function () {
	var passwd = Buffer.from("Correct Horse Battery Staple", "ascii");
	var salt = Buffer.from(">A 16-bytes salt", "ascii");
	var out, out2, result;

	it('crypto_pwhash_argon2i_str', function() {	
		out = sodium.crypto_pwhash_argon2i_str(passwd, OPSLIMIT, MEMLIMIT);
		assert(out);

		out2 = sodium.crypto_pwhash_argon2i_str(passwd, OPSLIMIT, MEMLIMIT);
		assert(out2);
		assert(!out.equals(out2));
	});

	it('crypto_pwhash_argon2i_str_needs_rehash false positive', function() {
		result = sodium.crypto_pwhash_argon2i_str_needs_rehash(out, OPSLIMIT, MEMLIMIT) 
		assert(result);
	});
		
	it('crypto_pwhash_argon2i_str_needs_rehash false negative', function() {
		assert(!sodium.crypto_pwhash_argon2i_str_needs_rehash(out, OPSLIMIT, MEMLIMIT / 2));
		assert(!sodium.crypto_pwhash_argon2i_str_needs_rehash(out, OPSLIMIT / 2, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2i_str_needs_rehash(out, OPSLIMIT, MEMLIMIT * 2));
		assert(!sodium.crypto_pwhash_argon2i_str_needs_rehash(out, OPSLIMIT * 2, MEMLIMIT));
	});

	it('crypto_pwhash_argon2i_str_needs_rehash didn\'t handle argon2i', function() {
		assert(!sodium.crypto_pwhash_str_needs_rehash(out, OPSLIMIT, MEMLIMIT / 2));
	});

	it('crypto_pwhash_argon2i_str_needs_rehash should fail with an invalid hash string', function() {
		var out3 = Buffer.allocUnsafe(out.length).fill(0);
		out.copy(out3);
		out3[0]++;
		assert(!sodium.crypto_pwhash_str_needs_rehash(out3, OPSLIMIT, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2i_str_needs_rehash(out3, OPSLIMIT, MEMLIMIT));
	});

	it('crypto_pwhash_argon2i_str proper pad', function() {
		var out_str = out.toString();
		var padding = out.slice(out_str.length);
		result = sodium.is_zero(padding);
		assert(result != -1);

		var out2_str = out2.toString();
		var padding2 = out2.slice(out2_str.length);
		result = sodium.is_zero(padding2);
		assert(result != -1);
	});

	it('crypto_pwhash_argon2i_str_verify should work', function() {
		assert(sodium.crypto_pwhash_argon2i_str_verify(out, passwd));
	});

	it('crypto_pwhash_argon2i_str_verify should not work with invalid hash', function() {
		var out3 = Buffer.allocUnsafe(out.length).fill(0);
		out.copy(out3);
		out3[14]++;
		assert(!sodium.crypto_pwhash_argon2i_str_verify(out3, passwd));
    });
    
	it('crypto_pwhash_argon2i_str_verify should produce valid strings', function() {
    	assert(out[sodium.crypto_pwhash_STRBYTES - 1] == 0);
	});

	it('crypto_pwhash_argon2i_str with a small opslimit should fail', function() {
		assert(!sodium.crypto_pwhash_argon2i_str(passwd, 1, MEMLIMIT));
	});

	it('crypto_pwhash_argon2i_str_verify invalid(1))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$m=65536,t=2,p=1c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_argon2i_str_verify(hash, passwd));
    });

	it('crypto_pwhash_argon2i_str_verify invalid(2))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_argon2i_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(3))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$b2G3seW+uPzerwQQC+/E1K50CLLO7YXy0JRcaTuswRo");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(4))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(5))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQwWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(6))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$8iIuixkI73Js3G1uMbezQXD0b8LG4SXGsOwoQkdAQIM");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });
	
	it('crypto_pwhash_str_verify valid(7))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=19$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(sodium.crypto_pwhash_str_verify(hash, passwd));
    });
	
	it('crypto_pwhash_str_verify valid(7))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=19$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("passwore", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(8))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$Argon2i$v=19$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(9))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=1$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(10))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=1$m=4096,t=3,p=2$b2RpZHVla~=mRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(11))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=1$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYI~=U+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_alg', function() {
		var result = sodium.crypto_pwhash_str_alg(Buffer.from("test"), OPSLIMIT, MEMLIMIT,
                                 sodium.crypto_pwhash_ALG_ARGON2I13);
		assert(result !== null);
	});
	
	it('crypto_pwhash_argon2i_str_verify', function() {
    	assert(!sodium.crypto_pwhash_argon2i_str_verify(out, Buffer.from("test")));
	});

	it('crypto_pwhash_argon2i_str_needs_rehash', function() {
		var out3 = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2i_strbytes());
		out.copy(out3, 1);

		assert(sodium.crypto_pwhash_argon2i_str_needs_rehash(out, OPSLIMIT, MEMLIMIT));
    	assert(!sodium.crypto_pwhash_argon2i_str_needs_rehash(out, OPSLIMIT / 2, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2i_str_needs_rehash(out,OPSLIMIT, MEMLIMIT / 2));
		assert(!sodium.crypto_pwhash_argon2i_str_needs_rehash(out, 0, 0));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, 0, 0));
		assert(!sodium.crypto_pwhash_argon2i_str_needs_rehash(out3, OPSLIMIT, MEMLIMIT));
		assert(sodium.crypto_pwhash_str_alg(Buffer.from("test"), OPSLIMIT, MEMLIMIT,
									sodium.crypto_pwhash_ALG_ARGON2ID13));
		assert(!sodium.crypto_pwhash_argon2id_str_verify(out, Buffer.from("test")));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT / 2, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT, MEMLIMIT / 2));
		var out4 = Buffer.alloc(sodium.crypto_pwhash_argon2id_strbytes());
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out4, OPSLIMIT, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out4, OPSLIMIT, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out3,OPSLIMIT, MEMLIMIT));
	});

	it('crypto_pwhash constants', function() {
		assert(sodium.crypto_pwhash_argon2i_bytes_min() > 0);
		assert(sodium.crypto_pwhash_argon2i_bytes_max() > sodium.crypto_pwhash_argon2i_bytes_min());
		assert(sodium.crypto_pwhash_argon2i_passwd_max() > sodium.crypto_pwhash_argon2i_passwd_min());
		assert(sodium.crypto_pwhash_argon2i_saltbytes() > 0);
		assert(sodium.crypto_pwhash_argon2i_strbytes() > 1);
		assert(sodium.crypto_pwhash_argon2i_strbytes() > sodium.crypto_pwhash_argon2i_strprefix().length);

		assert(sodium.crypto_pwhash_argon2i_opslimit_min() > 0);
		assert(sodium.crypto_pwhash_argon2i_opslimit_max() > 0);
		assert(sodium.crypto_pwhash_argon2i_memlimit_min() > 0);
		assert(sodium.crypto_pwhash_argon2i_memlimit_max() > 0);
		assert(sodium.crypto_pwhash_argon2i_opslimit_interactive() > 0);
		assert(sodium.crypto_pwhash_argon2i_memlimit_interactive() > 0);
		assert(sodium.crypto_pwhash_argon2i_opslimit_moderate() > 0);
		assert(sodium.crypto_pwhash_argon2i_memlimit_moderate() > 0);
		assert(sodium.crypto_pwhash_argon2i_opslimit_sensitive() > 0);
		assert(sodium.crypto_pwhash_argon2i_memlimit_sensitive() > 0);

		assert(sodium.crypto_pwhash_argon2i_bytes_min() == sodium.crypto_pwhash_argon2i_BYTES_MIN);
		assert(sodium.crypto_pwhash_argon2i_bytes_max() == sodium.crypto_pwhash_argon2i_BYTES_MAX);
		assert(sodium.crypto_pwhash_argon2i_passwd_min() == sodium.crypto_pwhash_argon2i_PASSWD_MIN);
		assert(sodium.crypto_pwhash_argon2i_passwd_max() == sodium.crypto_pwhash_argon2i_PASSWD_MAX);
		assert(sodium.crypto_pwhash_argon2i_saltbytes() == sodium.crypto_pwhash_argon2i_SALTBYTES);
		assert(sodium.crypto_pwhash_argon2i_strbytes() == sodium.crypto_pwhash_argon2i_STRBYTES);

		assert(sodium.crypto_pwhash_argon2i_opslimit_min() == sodium.crypto_pwhash_argon2i_OPSLIMIT_MIN);
		assert(sodium.crypto_pwhash_argon2i_opslimit_max() == sodium.crypto_pwhash_argon2i_OPSLIMIT_MAX);
		assert(sodium.crypto_pwhash_argon2i_memlimit_min() == sodium.crypto_pwhash_argon2i_MEMLIMIT_MIN);
		assert(sodium.crypto_pwhash_argon2i_memlimit_max() == sodium.crypto_pwhash_argon2i_MEMLIMIT_MAX);
		assert(sodium.crypto_pwhash_argon2i_opslimit_interactive() ==
			sodium.crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE);
		assert(sodium.crypto_pwhash_argon2i_memlimit_interactive() ==
			sodium.crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE);
		assert(sodium.crypto_pwhash_argon2i_opslimit_moderate() ==
			sodium.crypto_pwhash_argon2i_OPSLIMIT_MODERATE);
		assert(sodium.crypto_pwhash_argon2i_memlimit_moderate() ==
			sodium.crypto_pwhash_argon2i_MEMLIMIT_MODERATE);
		assert(sodium.crypto_pwhash_argon2i_opslimit_sensitive() ==
			sodium.crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE);
		assert(sodium.crypto_pwhash_argon2i_memlimit_sensitive() ==
			sodium.crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE);

		assert(sodium.crypto_pwhash_argon2i_alg_argon2i13() == sodium.crypto_pwhash_argon2i_ALG_ARGON2I13);
	})
});