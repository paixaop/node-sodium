var assert = require('assert');
var sodium = require('../build/Release/sodium');

var OPSLIMIT = 3
var MEMLIMIT = 5000000;

describe("libsodium_pwhash_argon2id", function () {
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
            "18acec5d6507739f203d1f5d9f1d862f7c2cdac4f19d2bdff64487e60d969e3ced615337b9eec6ac4461c6ca07f0939741e57c24d0005c7ea171a0ee1e7348249d135b38f222e4dad7b9a033ed83f5ca27277393e316582033c74affe2566a2bea47f91f0fd9fe49ece7e1f79f3ad6e9b23e0277c8ecc4b313225748dd2a80f5679534a0700e246a79a49b3f74eb89ec6205fe1eeb941c73b1fcf1",
            "26bab5f101560e48c711da4f05e81f5a3802b7a93d5155b9cab153069cc42b8e9f910bfead747652a0708d70e4de0bada37218bd203a1201c36b42f9a269b675b1f30cfc36f35a3030e9c7f57dfba0d341a974c1886f708c3e8297efbfe411bb9d51375264bd7c70d57a8a56fc9de2c1c97c08776803ec2cd0140bba8e61dc0f4ad3d3d1a89b4b710af81bfe35a0eea193e18a6da0f5ec05542c9eefc4584458e1da715611ba09617384748bd43b9bf1f3a6df4ecd091d0875e08d6e2fd8a5c7ce08904b5160cd38167b76ec76ef2d310049055a564da23d4ebd2b87e421cc33c401e12d5cd8d936c9baf75ebdfb557d342d2858fc781da31860",
            "6eb45e668582d63788ca8f6e930ca60b045a795fca987344f9a7a135aa3b5132b50a34a3864c26581f1f56dd0bcbfafbfa92cd9bff6b24a734cfe88f854aef4bda0a7983120f44936e8ff31d29728ac08ccce6f3f916b3c63962755c23a1fa9bb4e8823fc867bfd18f28980d94bc5874423ab7f96cc0ab78d8fa21fbd00cd3a1d96a73fa439ccc3fc4eab1590677b06cc78b0f674dfb680f23022fb902022dd8620803229c6ddf79a8156ccfce48bbd76c05ab670634f206e5b2e896230baa74a856964dbd8511acb71d75a1506766a125d8ce037f1db72086ebc3bccaefbd8cd9380167c2530386544ebfbeadbe237784d102bb92a10fd242",
            "",
            "08d8cd330c57e1b4643241d05bb468ba4ee4e932cd0858816be9ef15360b27bbd06a87130ee92222be267a29b81f5ae8fe8613324cfc4832dc49387fd0602f1c57b4d0f3855db94fb7e12eb05f9a484aed4a4307abf586cd3d55c809bc081541e00b682772fb2066504ff935b8ebc551a2083882f874bc0fae68e56848ae34c91097c3bf0cca8e75c0797eef3efde3f75e005815018db3cf7c109a812264c4de69dcb22322dbbcfa447f5b00ecd1b04a7be1569c8e556adb7bba48adf81d",
            "d6e9d6cabd42fb9ba7162fe9b8e41d59d3c7034756cb460c9affe393308bd0225ce0371f2e6c3ca32aca2002bf2d3909c6b6e7dfc4a00e850ff4f570f8f749d4bb6f0091e554be67a9095ae1eefaa1a933316cbec3c2fd4a14a5b6941bda9b7eabd821d79abde2475a53af1a8571c7ee46460be415882e0b393f48c12f740a6a72cba9773000602e13b40d3dfa6ac1d4ec43a838b7e3e165fecad4b2498389e60a3ff9f0f8f4b9fca1126e64f49501e38690",
            "7fb72409b0987f8190c3729710e98c3f80c5a8727d425fdcde7f3644d467fe973f5b5fee683bd3fce812cb9ae5e9921a2d06c2f1905e4e839692f2b934b682f11a2fe2b90482ea5dd234863516dba6f52dc0702d324ec77d860c2e181f84472bd7104fedce071ffa93c5309494ad51623d214447a7b2b1462dc7d5d55a1f6fd5b54ce024118d86f0c6489d16545aaa87b6689dad9f2fb47fda9894f8e12b87d978b483ccd4cc5fd9595cdc7a818452f915ce2f7df95ec12b1c72e3788d473441d884f9748eb14703c21b45d82fd667b85f5b2d98c13303b3fe76285531a826b6fc0fe8e3dddecf",
            "4e702bc5f891df884c6ddaa243aa846ce3c087fe930fef0f36b3c2be34164ccc295db509254743f18f947159c813bcd5dd8d94a3aec93bbe57605d1fad1aef1112687c3d4ef1cb329d21f1632f626818d766915d886e8d819e4b0b9c9307f4b6afc081e13b0cf31db382ff1bf05a16aac7af696336d75e99f82163e0f371e1d25c4add808e215697ad3f779a51a462f8bf52610af21fc69dba6b072606f2dabca7d4ae1d91d919",
            "20e7ba6faa2c0a4b07f3ff38e15e252a069c2c62bac3f2785d311764d73e67fd713be342ee938e6df4de6af1a89a44b8589838864457bcfe3cf0f2d329b800ab9f5810b6325588eb4e0c56f99192b2cc76dc8194dc1097fe5ed12ac4214481c03c3597131ba164a56e7187e2da565a8cd529668e9a37faa58a1701c49a14edf7a50dec4143b456cba6d14c957bb655e99ce96bc506961216ef887a",
            "8fb6ed1862cdd2a399e10956c60dc9b2670338ea59c3414d0443216925ba24c6e89a17f3e56c12893dcbc9bc498e8308aea9627d9c9e47912d6342b631008719edfa2db364b97e60cf47a97ad9aa3b7f139d80ddda44f1ef2af881ce027a15644218cac6cc74751469ae56be0469fbc760825882b3e8abca55daaae5753575106cf867cd69932602c63ec880ad8811d9aa4870a9e0b39fef47c92e",
            "",
            "",
            ""
        ];

        for(var i  = 0; i < tests.length; i++) {
            var passwd = Buffer.from(tests[i][0], 'hex');
            var passwd_len = tests[i][1];
            var salt = Buffer.from(tests[i][2], 'hex').slice(0, sodium.crypto_pwhash_saltbytes());
            var outlen = tests[i][3];
            var opslimit  = tests[i][4];
            var memlimit = tests[i][5];
            var lanes = tests[i][6];
            var alg = sodium.crypto_pwhash_alg_default();
    
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

		out = sodium.crypto_pwhash_argon2id(outLen, passwd, salt, 3, 1 << 12, 0);
		assert(out === null);
		 
		out = sodium.crypto_pwhash(outLen, passwd, salt, 3, 1,
			sodium.crypto_pwhash_argon2id_alg_argon2id13());
		assert(out === null);

		out = sodium.crypto_pwhash(outLen, passwd, salt, 3, 1 << 12,
			sodium.crypto_pwhash_argon2id_alg_argon2id13());
		assert(out === null);
		
		out = sodium.crypto_pwhash(outLen, passwd, salt, 2, 1 << 12,
			sodium.crypto_pwhash_argon2id_alg_argon2id13());
		assert(out === null);
		
		out = sodium.crypto_pwhash(15, passwd, salt, 3, 1 << 12,
			sodium.crypto_pwhash_argon2id_alg_argon2id13());
		assert(out === null);

		out = sodium.crypto_pwhash_argon2id(outLen, passwd, salt, OPSLIMIT, MEMLIMIT, 
			sodium.crypto_pwhash_alg_argon2i13());
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

describe("libsodium_pwhash_argon2id str tests", function () {
	var passwd = Buffer.from("Correct Horse Battery Staple", "ascii");
	var salt = Buffer.from(">A 16-bytes salt", "ascii");
	var out, out2, result;

	it('crypto_pwhash_argon2id_str', function() {	
		out = sodium.crypto_pwhash_argon2id_str(passwd, OPSLIMIT, MEMLIMIT);
		assert(out);

		out2 = sodium.crypto_pwhash_argon2id_str(passwd, OPSLIMIT, MEMLIMIT);
		assert(out2);
		assert(!out.equals(out2));
	});

	it('crypto_pwhash_argon2id_str_needs_rehash false positive', function() {
		result = sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT, MEMLIMIT) 
		assert(result);
	});
		
	it('crypto_pwhash_argon2id_str_needs_rehash false negative', function() {
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT, MEMLIMIT / 2));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT / 2, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT, MEMLIMIT * 2));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT * 2, MEMLIMIT));
	});

	it('crypto_pwhash_argon2id_str_needs_rehash didn\'t handle argon2i', function() {
		assert(!sodium.crypto_pwhash_str_needs_rehash(out, OPSLIMIT, MEMLIMIT / 2));
	});

	it('crypto_pwhash_argon2id_str_needs_rehash should fail with an invalid hash string', function() {
		var out3 = Buffer.allocUnsafe(out.length).fill(0);
		out.copy(out3);
		out3[0]++;
		assert(!sodium.crypto_pwhash_str_needs_rehash(out3, OPSLIMIT, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out3, OPSLIMIT, MEMLIMIT));
	});

	it('crypto_pwhash_argon2id_str proper pad', function() {
		var out_str = out.toString();
		var padding = out.slice(out_str.length);
		result = sodium.is_zero(padding);
		assert(result != -1);

		var out2_str = out2.toString();
		var padding2 = out2.slice(out2_str.length);
		result = sodium.is_zero(padding2);
		assert(result != -1);
	});

	it('crypto_pwhash_argon2id_str_verify should work', function() {
		assert(sodium.crypto_pwhash_argon2id_str_verify(out, passwd));
	});

	it('crypto_pwhash_argon2id_str_verify should not work with invalid hash', function() {
		var out3 = Buffer.allocUnsafe(out.length).fill(0);
		out.copy(out3);
		out3[14]++;
		assert(!sodium.crypto_pwhash_argon2id_str_verify(out3, passwd));
    });
    
	it('crypto_pwhash_argon2id_str_verify should produce valid strings', function() {
    	assert(out[sodium.crypto_pwhash_STRBYTES - 1] == 0);
	});

	it('crypto_pwhash_argon2id_str with a small opslimit should not fail', function() {
		assert(sodium.crypto_pwhash_argon2id_str(passwd, 1, MEMLIMIT));
	});

	it('crypto_pwhash_argon2id_str_verify invalid(1))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$m=65536,t=2,p=1c29tZXNhbHQ$9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_argon2id_str_verify(hash, passwd));
    });

	it('crypto_pwhash_argon2id_str_verify invalid(2))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ9sTbSlTio3Biev89thdrlKKiCaYsjjYVJxGAL3swxpQ");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_argon2id_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(3))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$b2G3seW+uPzerwQQC+/E1K50CLLO7YXy0JRcaTuswRo");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(4))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(5))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQwWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(6))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$8iIuixkI73Js3G1uMbezQXD0b8LG4SXGsOwoQkdAQIM");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });
	
	it('crypto_pwhash_str_verify valid(7))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=19$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(sodium.crypto_pwhash_str_verify(hash, passwd));
    });
	
	it('crypto_pwhash_str_verify valid(7))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=19$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("passwore", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(8))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$Argon2i$v=19$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(9))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=1$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(10))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=1$m=4096,t=3,p=2$b2RpZHVla~=mRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYIU+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_verify invalid(11))', function() {
		var hash = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes()).fill(0);
		var bStr = Buffer.from("$argon2i$v=1$m=4096,t=3,p=2$b2RpZHVlamRpc29kaXNrdw$TNnWIwlu1061JHrnCqIAmjs3huSxYI~=U+0jWipu7Kc9M");
		bStr.copy(hash);
		var passwd = Buffer.from("password", "ascii");
    	assert(!sodium.crypto_pwhash_str_verify(hash, passwd));
    });

	it('crypto_pwhash_str_alg', function() {
		var result = sodium.crypto_pwhash_str_alg(Buffer.from("test"), OPSLIMIT, MEMLIMIT,
                                 sodium.crypto_pwhash_argon2id_alg_argon2id13());
		assert(result !== null);
	});
	
	it('crypto_pwhash_argon2id_str_verify', function() {
    	assert(!sodium.crypto_pwhash_argon2id_str_verify(out, Buffer.from("test")));
	});

	it('crypto_pwhash_argon2id_str_needs_rehash', function() {
		var out3 = Buffer.allocUnsafe(sodium.crypto_pwhash_argon2id_strbytes());
		out.copy(out3, 1);

		assert(sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT, MEMLIMIT));
    	assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT / 2, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out,OPSLIMIT, MEMLIMIT / 2));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, 0, 0));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, 0, 0));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out3, OPSLIMIT, MEMLIMIT));
		assert(sodium.crypto_pwhash_str_alg(Buffer.from("test"), OPSLIMIT, MEMLIMIT,
									sodium.crypto_pwhash_ALG_ARGON2ID13));
		assert(!sodium.crypto_pwhash_argon2id_str_verify(out, Buffer.from("test")));
		assert(sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT / 2, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out, OPSLIMIT, MEMLIMIT / 2));
		var out4 = Buffer.alloc(sodium.crypto_pwhash_argon2id_strbytes());
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out4, OPSLIMIT, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out4, OPSLIMIT, MEMLIMIT));
		assert(!sodium.crypto_pwhash_argon2id_str_needs_rehash(out3,OPSLIMIT, MEMLIMIT));
	});

	it('crypto_pwhash constants', function() {
		assert(sodium.crypto_pwhash_argon2id_bytes_min() > 0);
		assert(sodium.crypto_pwhash_argon2id_bytes_max() > sodium.crypto_pwhash_argon2id_bytes_min());
		assert(sodium.crypto_pwhash_argon2id_passwd_max() > sodium.crypto_pwhash_argon2id_passwd_min());
		assert(sodium.crypto_pwhash_argon2id_saltbytes() > 0);
		assert(sodium.crypto_pwhash_argon2id_strbytes() > 1);
		assert(sodium.crypto_pwhash_argon2id_strbytes() > sodium.crypto_pwhash_argon2id_strprefix().length);

		assert(sodium.crypto_pwhash_argon2id_opslimit_min() > 0);
		assert(sodium.crypto_pwhash_argon2id_opslimit_max() > 0);
		assert(sodium.crypto_pwhash_argon2id_memlimit_min() > 0);
		assert(sodium.crypto_pwhash_argon2id_memlimit_max() > 0);
		assert(sodium.crypto_pwhash_argon2id_opslimit_interactive() > 0);
		assert(sodium.crypto_pwhash_argon2id_memlimit_interactive() > 0);
		assert(sodium.crypto_pwhash_argon2id_opslimit_moderate() > 0);
		assert(sodium.crypto_pwhash_argon2id_memlimit_moderate() > 0);
		assert(sodium.crypto_pwhash_argon2id_opslimit_sensitive() > 0);
		assert(sodium.crypto_pwhash_argon2id_memlimit_sensitive() > 0);

		assert(sodium.crypto_pwhash_argon2id_bytes_min() == sodium.crypto_pwhash_argon2id_BYTES_MIN);
		assert(sodium.crypto_pwhash_argon2id_bytes_max() == sodium.crypto_pwhash_argon2id_BYTES_MAX);
		assert(sodium.crypto_pwhash_argon2id_passwd_min() == sodium.crypto_pwhash_argon2id_PASSWD_MIN);
		assert(sodium.crypto_pwhash_argon2id_passwd_max() == sodium.crypto_pwhash_argon2id_PASSWD_MAX);
		assert(sodium.crypto_pwhash_argon2id_saltbytes() == sodium.crypto_pwhash_argon2id_SALTBYTES);
		assert(sodium.crypto_pwhash_argon2id_strbytes() == sodium.crypto_pwhash_argon2id_STRBYTES);

		assert(sodium.crypto_pwhash_argon2id_opslimit_min() == sodium.crypto_pwhash_argon2id_OPSLIMIT_MIN);
		assert(sodium.crypto_pwhash_argon2id_opslimit_max() == sodium.crypto_pwhash_argon2id_OPSLIMIT_MAX);
		assert(sodium.crypto_pwhash_argon2id_memlimit_min() == sodium.crypto_pwhash_argon2id_MEMLIMIT_MIN);
		assert(sodium.crypto_pwhash_argon2id_memlimit_max() == sodium.crypto_pwhash_argon2id_MEMLIMIT_MAX);
		assert(sodium.crypto_pwhash_argon2id_opslimit_interactive() ==
			sodium.crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE);
		assert(sodium.crypto_pwhash_argon2id_memlimit_interactive() ==
			sodium.crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE);
		assert(sodium.crypto_pwhash_argon2id_opslimit_moderate() ==
			sodium.crypto_pwhash_argon2id_OPSLIMIT_MODERATE);
		assert(sodium.crypto_pwhash_argon2id_memlimit_moderate() ==
			sodium.crypto_pwhash_argon2id_MEMLIMIT_MODERATE);
		assert(sodium.crypto_pwhash_argon2id_opslimit_sensitive() ==
			sodium.crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE);
		assert(sodium.crypto_pwhash_argon2id_memlimit_sensitive() ==
			sodium.crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE);

		assert(sodium.crypto_pwhash_argon2i_alg_argon2i13() == sodium.crypto_pwhash_argon2i_ALG_ARGON2I13);
	})
});