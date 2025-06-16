var assert = require('assert');
var sodium = require('../build/Release/sodium');

var OPSLIMIT = 1000000;
var MEMLIMIT = 10000000;

describe("libsodium_pwhash_scrypt", function () {
    it("Test Vectors 1 - crypto_pwhash_scryptsalsa208sha256", function() {
        var tests = [
            [ 
                "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae0" +
                "65577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d" +
                "a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f5" +
                "8d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6",
                127,
                "5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2",
                155, 481326, 7256678 
            ],
            [ "e125cee61c8cb7778d9e5ad0a6f5d978ce9f84de213a8556d9ffe202020ab4a6ed" +
                "9074a4eb3416f9b168f137510f3a30b70b96cbfa219ff99f6c6eaffb15c06b60e0" +
                "0cc2890277f0fd3c622115772f7048adaebed86e",
                86,
                "f1192dd5dc2368b9cd421338b22433455ee0a3699f9379a08b9650ea2c126f0d",
                250, 535778, 7849083 
            ],
            [ 
                "92263cbf6ac376499f68a4289d3bb59e5a22335eba63a32e6410249155b956b6a3" +
                "b48d4a44906b18b897127300b375b8f834f1ceffc70880a885f47c33876717e392" +
                "be57f7da3ae58da4fd1f43daa7e44bb82d3717af4319349c24cd31e46d295856b0" +
                "441b6b289992a11ced1cc3bf3011604590244a3eb737ff221129215e4e4347f491" +
                "5d41292b5173d196eb9add693be5319fdadc242906178bb6c0286c9b6ca6012746" +
                "711f58c8c392016b2fdfc09c64f0f6b6ab7b",
                183,
                "3b840e20e9555e9fb031c4ba1f1747ce25cc1d0ff664be676b9b4a90641ff194",
                249, 311757, 7994791 
            ],
            [ 
                "027b6d8e8c8c474e9b69c7d9ed4f9971e8e1ce2f6ba95048414c3970f0f09b70e3" +
                "b6c5ae05872b3d8678705b7d381829c351a5a9c88c233569b35d6b0b809df44b64" +
                "51a9c273f1150e2ef8a0b5437eb701e373474cd44b97ef0248ebce2ca0400e1b53" +
                "f3d86221eca3f18eb45b702b9172440f774a82cbf1f6f525df30a6e293c873cce6" +
                "9bb078ed1f0d31e7f9b8062409f37f19f8550aae",
                152,
                "eb2a3056a09ad2d7d7f975bcd707598f24cd32518cde3069f2e403b34bfee8a5", 5,
                643464, 1397645 
            ],
            [ 
                "4a857e2ee8aa9b6056f2424e84d24a72473378906ee04a46cb05311502d5250b82" +
                "ad86b83c8f20a23dbb74f6da60b0b6ecffd67134d45946ac8ebfb3064294bc097d" +
                "43ced68642bfb8bbbdd0f50b30118f5e",
                82,
                "39d82eef32010b8b79cc5ba88ed539fbaba741100f2edbeca7cc171ffeabf258",
                190, 758010, 5432947 
            ],
            [ 
                "1845e375479537e9dd4f4486d5c91ac72775d66605eeb11a787b78a7745f1fd005" +
                "2d526c67235dbae1b2a4d575a74cb551c8e9096c593a497aee74ba3047d911358e" +
                "de57bc27c9ea1829824348daaab606217cc931dcb6627787bd6e4e5854f0e8",
                97,
                "3ee91a805aa62cfbe8dce29a2d9a44373a5006f4a4ce24022aca9cecb29d1473",
                212, 233177, 13101817 
            ],
            [ 
                "c7b09aec680e7b42fedd7fc792e78b2f6c1bea8f4a884320b648f81e8cf515e8ba" +
                "9dcfb11d43c4aae114c1734aa69ca82d44998365db9c93744fa28b63fd16000e82" +
                "61cbbe083e7e2da1e5f696bde0834fe53146d7e0e35e7de9920d041f5a5621aabe" +
                "02da3e2b09b405b77937efef3197bd5772e41fdb73fb5294478e45208063b5f58e" +
                "089dbeb6d6342a909c1307b3fff5fe2cf4da56bdae50848f",
                156,
                "039c056d933b475032777edbaffac50f143f64c123329ed9cf59e3b65d3f43b6",
                178, 234753, 4886999 
            ],
            [ 
                "8f3a06e2fd8711350a517bb12e31f3d3423e8dc0bb14aac8240fca0995938d59bb" +
                "37bd0a7dfc9c9cc0705684b46612e8c8b1d6655fb0f9887562bb9899791a0250d1" +
                "320f945eda48cdc20c233f40a5bb0a7e3ac5ad7250ce684f68fc0b8c9633bfd75a" +
                "ad116525af7bdcdbbdb4e00ab163fd4df08f243f12557e",
                122,
                "90631f686a8c3dbc0703ffa353bc1fdf35774568ac62406f98a13ed8f47595fd",
                55, 695191, 15738350 
            ],
            [ 
                "b540beb016a5366524d4605156493f9874514a5aa58818cd0c6dfffaa9e90205f1" +
                "7b",
                34,
                "44071f6d181561670bda728d43fb79b443bb805afdebaf98622b5165e01b15fb",
                231, 78652, 6631659 
            ],
            [ 
                "a14975c26c088755a8b715ff2528d647cd343987fcf4aa25e7194a8417fb2b4b3f" +
                "7268da9f3182b4cfb22d138b2749d673a47ecc7525dd15a0a3c66046971784bb63" +
                "d7eae24cc84f2631712075a10e10a96b0e0ee67c43e01c423cb9c44e5371017e9c" +
                "496956b632158da3fe12addecb88912e6759bc37f9af2f45af72c5cae3b179ffb6" +
                "76a697de6ebe45cd4c16d4a9d642d29ddc0186a0a48cb6cd62bfc3dd229d313b30" +
                "1560971e740e2cf1f99a9a090a5b283f35475057e96d7064e2e0fc81984591068d" +
                "55a3b4169f22cccb0745a2689407ea1901a0a766eb99",
                220,
                "3d968b2752b8838431165059319f3ff8910b7b8ecb54ea01d3f54769e9d98daf",
                167, 717248, 10784179 
            ],
            [
                "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae0" +
                "65577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d" +
                "a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f5" +
                "8d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6",
                127,
                "5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2",
                155, 64, 1397645 
            ],
            [ 
                "a347ae92bce9f80f6f595a4480fc9c2fe7e7d7148d371e9487d75f5c23008ffae0" +
                "65577a928febd9b1973a5a95073acdbeb6a030cfc0d79caa2dc5cd011cef02c08d" +
                "a232d76d52dfbca38ca8dcbd665b17d1665f7cf5fe59772ec909733b24de97d6f5" +
                "8d220b20c60d7c07ec1fd93c52c31020300c6c1facd77937a597c7a6",
                127,
                "5541fbc995d5c197ba290346d2c559dedf405cf97e5f95482143202f9e74f5c2",
                155, 32768, 1397645 
            ]
        ];
            
        var expected = [
            "8d40f5f8c6a1791204f03e19a98cd74f918b6e331b39cfc2415e5014d7738b7bb0a83551fb14a035e07fdd4dc0c60c1a6822ac253918979f6324ff0c87cba75d3b91f88f41ca5414a0f152bdc4d636f42ab2250afd058c19ec31a3374d1bd7133289bf21513ff67cbf8482e626aee9864c58fd05f9ea02e508a10182b7d838157119866f072004987ef6c56683ed207705923921af9d76444a331a",
            "d985d4c278343a46d82af0c4268b7ae6b6d1d2dd289675ef45bfb6d0648bffe5bab8c91228f3a31b091154a9c1142670a07b92e70a298333066de07db9300e046fd7cacc99780804683df7babdfc9d019047178400b2875bde0a1ad824dda7a422d9ed48475af9a3876378dd3a2f206e34984e223afb82c0c1e4644c9a458f4666379fdd3e2d9206d87e3c32c3977f35826a27590baaa1ec1a3bd7d15a92bc84c95dcfc56c14fca7c4c9810162dfdf9dc08a191e79fe40250b7e07d3a9317d9a5cb56e1062c419a6cd6a9b73128e8ad79ab7efffbb3cc52c1f49f86d2ebb46e6e4846aecdb14c2d046f5380517ff8cc794e4a772a58b93083dad",
            "ee7e9e1369267ec555981f0ea088ff6f93953abfcb767d88ec3c46393d24cfbaba5e4e26e0f35b5d5259647748476d65cd8881c96f8cda049d9c877b2d33d932e67f4c0df2cb434b4b4900e0c49c3f8ba9663795420577e65d0b456201ad9162fbc485c7b44f2b34e6673aa3692c123021ee3b624c3bb22b808b89613d8ecc7b87da47f57152eb3f7b10ad206f6b09cb6935b347b5e42bc3b8c9c9bcd8d7b7c44929b367fc279dec48ea78e6ee3e2620d7459700bd0aedb1c9aa5a323ca94403927f5e5c2b73bda7c5c3287b62fe51874cfeb1dc3151cd886b26d83ece68833229d2d432798c602d85b0505947207d8430febbe901164b12ce",
            "",
            "bcc5c2fd785e4781d1201ed43d84925537e2a540d3de55f5812f29e9dd0a4a00451a5c8ddbb4862c03d45c75bf91b7fb49265feb667ad5c899fdbf2ca19eac67aa5e48595d5b02f8183ab07f71b1ce0d76e5df54919f63810ad0893ded7d1ca18fc956ec06ffd4c3d1f77a00ed53608947b25eea5df6bea02272be15815f974c321a2a9208674fdf59d1d798c2a12f1889df68b0c222b37ee9ef0d6391fc160b0281ec53073cb3a3706ce1d71c3af2f5237a1b3d8545d99012eecc0b4abb",
            "82765c040c58c1810f8c053ef5c248556299385476bde44bdd91a0d9a239f24e9b1717fd8b23209ffa45b7aa7937296c601b79e77da99e8d2fda0ea4459be2d0900f5bc5a269b5488d873d4632d1baf75965e509ee24b12501a9ce3bbbd8b7d759987d545a1c221a363195e5802d768b3b9e00ebe5ac0ed8ad2362c1c4157b910a40f94adf2561a2b0d3e65dbb06f244e5ac44d362103df54c9b9175777b3db1cdadb03e977ab8a79baf1e1e18ec9f5d0f25c487ddc53d7e81910f83576b44e9caeece26e2eb376569ad3a8cdccbde8bc355210e",
            "ca9216d4127e2e4a6ee3584b49be106217bb61cc807016d46d0cfbb1fd722e2bbac33541386bdfeac41a299ead22790993fcaa8e1d23bd1c8426afa5ff4c08e731dc476ef834f142c32dfb2c1be12b9978802e63b2cd6f226b1a8df59f0c79154d7ef4296a68ec654538d987104f9a11aca1b7c83ab2ed8fd69da6b88f0bcbd27d3fea01329cecf10c57ec3ba163d57b38801bd6c3b31ce527b33717bb56a46f78fb96be9f2424a21b3284232388cbba6a74",
            "2732a7566023c8db90a5fdd08dbe6c1b5e70c046d50c5735c8d86a589ba177f69db12d6cc3596319fa27c9e063ed05b8a31970a07dc905",
            "d7b1ef464be03ce9050b5108e25f0b8e821299986fe0ff89e17fbae65ba9fad167fbd265866ac03efc86ab0b50d46d6740a59adf5949b44f7f9f3ac3f3d4cc9f128966db9099deb1b6b78505242b2401a193820408eb0780b27162ebafb7c505b0e7c32ce66c6efc0be487008c1201454680498a2fc06e00b454e0b20933906bbb0e43b399b9ee46d882f107df1ebdd1e7cd867c9cdba6015b7e80064ae8b3417d969524bec046e782a13b125f058cd36b5d1ae65886ae7caab45a6d98651ada435b8ee11d5c1224232f5f515df974138dd6cf347b730481d4b073af8ff0394fe9f0b8cdfd99f5",
            "1839be14287053bfcd4ea60db82777fad1a6e9535c388b770743e61235449e668717199defd516c438b3ebd79b3529eb32482ef414525292ea1bbec09da10790a2330a4399f2fe6dd63d80954e3c547a5f1c619db5a30bde495b23f2214b4fa7572851d75246f2817775f0b521acc6efbc7832c9a76de7465e3c65cade88e86c973f85a882bb54f92b983977c6e937c88f083ba68c70fb49497065b158e2e789809b1d4cc9ec2d",
            "d54916748076b9d9f72198c8fbef563462dc8c706e1ad38abd1fac570016721acd0a7659ab49a47299a996b43597690c0c947143069f35d83e606273dbf2d622321393949b8ed5a68315362c4f84804384d05e0e0e86bc00e3641233f9f975ab46b60ba185c5e5fe47f78efd207e69fd8f6390730828b93b9b3763ea1283caa03bc36726763715de811915681dd214524f5ad4dd386608cac6c7f2",
            "d54916748076b9d9f72198c8fbef563462dc8c706e1ad38abd1fac570016721acd0a7659ab49a47299a996b43597690c0c947143069f35d83e606273dbf2d622321393949b8ed5a68315362c4f84804384d05e0e0e86bc00e3641233f9f975ab46b60ba185c5e5fe47f78efd207e69fd8f6390730828b93b9b3763ea1283caa03bc36726763715de811915681dd214524f5ad4dd386608cac6c7f2",
        ];
        
        for(var i  = 0; i < tests.length; i++) {
            var passwd = Buffer.from(tests[i][0], 'hex');
            var passwd_len = tests[i][1];
            var salt = Buffer.from(tests[i][2], 'hex').slice(0, sodium.crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
            var outlen = tests[i][3];
            var opslimit  = tests[i][4];
            var memlimit = tests[i][5];
            
            var out = sodium.crypto_pwhash_scryptsalsa208sha256(
                outlen, passwd,  salt, opslimit, memlimit
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
    
    it('Test Valid Vectors - crypto_pwhash_scryptsalsa208sha256_str_verify', function() {
        var tests = [
            [ 
                "^T5H$JYt39n%K*j:W]!1s?vg!:jGi]Ax?..l7[p0v:1jHTpla9;]bUN;?bWyCbtqg " +
                "nrDFal+Jxl3,2`#^tFSu%v_+7iYse8-cCkNf!tD=KrW)",
                "$7$B6....1....75gBMAGwfFWZqBdyF3WdTQnWdUsuTiWjG1fF9c1jiSD$tc8RoB3." +
                "Em3/zNgMLWo2u00oGIoTyJv4fl3Fl8Tix72"
            ],
            [ 
                "bl72h6#y<':MFRZ>B IA1=NRkCKS%W8`1I.2uQxJN0g)N N aTt^4K!Iw5r " +
                "H6;crDsv^a55j9tsk'/GqweZn;cdk6+F_St6:#*=?ZCD_lw>.",
                "$7$A6....3....Iahc6qM0.UQJHVgE4h9oa1/" +
                "4OWlWLm9CCtfguvz6bQD$QnXCo3M7nIqtry2WKsUZ5gQ.mY0wAlJu." +
                "WUhtE8vF66" 
            ],
            [ 
                "Py " +
                ">e.5b+tLo@rL`dC2k@eJ&4eVl!W=JJ4+k&mAt@gt',FS1JjqKW3aq21:]^kna`" +
                "mde7kVkN5NrpKUptu)@4*b&?BE_sJMG1=&@`3GBCV]Wg7xwgo7x3El",
                "$7$96..../....f6bEusKt79kK4wdYN0ki2nw4bJQ7P3rN6k3BSigsK/" +
                "D$Dsvuw7vXj5xijmrb/NOhdgoyK/OiSIYv88cEtl9Cik7"
            ],
            [ 
                "2vj;Um]FKOL27oam(:Uo8+UmSTvb1FD*h?jk_,S=;RDgF-$Fjk?]9yvfxe@fN^!NN(" +
                "Cuml?+2Raa",
                "$7$86....I....7XwIxLtCx4VphmFeUa6OGuGJrFaIaYzDiLNu/" +
                "tyUPhD$U3q5GCEqCWxMwh.YQHDJrlg7FIZgViv9pcXE3h1vg61" 
            ],
            [ 
                "CT=[9uUoGav,J`kU+348tA50ue#sL:ABZ3QgF+r[#vh:tTOiL>s8tv%,Jeo]jH/" +
                "_4^i(*jD-_ku[9Ko[=86 06V",
                
                "$7$A6....2....R3.bjH6YS9wz9z8Jsj.3weGQ3J80ZZElGw2oVux1TP6$" +
                "i5u6lFzXDHaIgYEICinLD6WNaovbiXP8SnLrDRdKgA9" 
            ],
            [ 
                "J#wNn`hDgOpTHNI.w^1a70%f,.9V_m038H_JIJQln`vdWnn/" +
                "rmILR?9H5g(+`;@H(2VosN9Fgk[WEjaBr'yB9Q19-imNa04[Mk5kvGcSn-TV",
                "$7$B6....1....Dj1y.4mF1J9XmT/6IDskYdCLaPFJTq9xcCwXQ1DpT92$92/" +
                "hYfZLRq1nTLyIz.uc/dC6wLqwnsoqpkadrCXusm6" 
            ],
            [ 
                "j4BS38Asa;p)[K+9TY!3YDj<LK-`nLVXQw9%*QfM",
                "$7$B6....1....5Ods8mojVwXJq4AywF/uI9BdMSiJ/zT8hQP/" +
                "4cB68VC$nk4ExHNXJ802froj51/1wJTrSZvTIyyK7PecOxRRaz0" 
            ],
            [ 
                "M.R>Qw+!qJb]>pP :_.9`dxM9k [eR7Y!yL-3)sNs[R,j_/^ " +
                "TH=5ny'15>6UXWcQW^6D%XCsO[vN[%ReA-`tV1vW(Nt*0KVK#]45P_A",
                "$7$B6....1....D/" +
                "eyk8N5y6Z8YVQEsw521cTx.9zzLuK7YDs1KMMh.o4$alfW8ZbsUWnXc." +
                "vqon2zoljVk24Tt1.IsCuo2KurvS2" 
            ],
            [ // 8
                "K3S=KyH#)36_?]LxeR8QNKw6X=gFb'ai$C%29V* " +
                "tyh^Wo$TN-#Q4qkmtTCf0LLb.^E$0uykkP",
                "$7$B6....1....CuBuU97xgAage8whp/" +
                "JNKobo0TFbsORGVbfcQIefyP8$aqalP." +
                "XofGViB8EPLONqHma8vs1xc9uTIMYh9CgE.S8" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7$A6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
        ];
        
        for(var i  = 0; i < tests.length; i++) {
            var passwd = Buffer.from(tests[i][0]);
            var hash = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES);
            var out = Buffer.from(tests[i][1]);
            out.copy(hash, 0);

            var result = sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(hash, passwd);
            assert(result, "Test vector " + i);
        }
    });

    it('Test Invalid Vectors - crypto_pwhash_scryptsalsa208sha256_str_verify', function() {
        /* Invalid pwhash strings */
        var tests= [
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7$A6....1....$TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7$.6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7$A.....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7$A6.........TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7$A6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i44269$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AH" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7$A6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx54269" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7^A6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7$!6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7$A!....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7$A6....!....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [ 
                "",
                "$7$A6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7fA6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4#" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [ 
                "Y0!?iQa9M%5ekffW(`",
                "$7$AX....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [  
                "Y0!?iQa9M%5ekffW(`",
                "$7$A6....1!...TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" +
                "a4ik5hGDN7foMuHOW.cp.CtX01UyCeO0.JAG.AHPpx5" 
            ],
            [ "Y0!?iQa9M%5ekffW(`", "$7$A6....1" ],
            [ "Y0!?iQa9M%5ekffW(`", "$7$" ],
            [ "Y0!?iQa9M%5ekffW(`", "" ],
            [ "Y0!?iQa9M%5ekffW(`",
              "$7$A6....1....TrXs5Zk6s8sWHpQgWDIXTR8kUU3s6Jc3s.DtdS8M2i4$" ],
            [ "test",
              "$7$.6..../.....lgPchkGHqbeONR/xtuXyjCrt9kUSg6NlKFQO0OSxo/$.DbajbPYH9T7sg3fOtcgxvJzzfIgJBIxMkeQ8b24YQ." ],
            [ "test",
              "$7$z6..../.....lgPchkGHqbeONR/xtuXyjCrt9kUSg6NlKFQO0OSxo/$.DbajbPYH9T7sg3fOtcgxvJzzfIgJBIxMkeQ8b24YQ." ],
            [ "test",
              "$7$8zzzzz/.....lgPchkGHqbeONR/xtuXyjCrt9kUSg6NlKFQO0OSxo/$.DbajbPYH9T7sg3fOtcgxvJzzfIgJBIxMkeQ8b24YQ." ],
            [ "test",
              "$7$8zzzzzzzzzz.lgPchkGHqbeONR/xtuXyjCrt9kUSg6NlKFQO0OSxo/$.DbajbPYH9T7sg3fOtcgxvJzzfIgJBIxMkeQ8b24YQ." ],
            [ "test",
              "$7$8.....zzzzz.lgPchkGHqbeONR/xtuXyjCrt9kUSg6NlKFQO0OSxo/$.DbajbPYH9T7sg3fOtcgxvJzzfIgJBIxMkeQ8b24YQ." ],
            [ "test",
              "$7$86..../..../lgPchkGHqbeONR/xtuXyjCrt9kUSg6NlKFQO0OSxo/$.DbajbPYH9T7sg3fOtcgxvJzzfIgJBIxMkeQ8b24YQ." ]
        ];
        
        for(var i  = 0; i < tests.length; i++) {
            var passwd = Buffer.from(tests[i][0]);
            var hash = Buffer.alloc(sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES);
            var out = Buffer.from(tests[i][1]);
            out.copy(hash, 0);
            
            var result = sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(hash, passwd);
            assert(!result, "Test invalid vector " + i);
        }

    });


});
            
describe("crypto_pwhash_scryptsalsa208sha256_str tests", function () {
    var passwd = Buffer.from("Correct Horse Battery Staple", "ascii");
    var salt = Buffer.from("[<~A 32-bytes salt for scrypt~>]", "ascii");
    var result;
    var out = sodium.crypto_pwhash_scryptsalsa208sha256_str(passwd, OPSLIMIT, MEMLIMIT);
    var out2 = sodium.crypto_pwhash_scryptsalsa208sha256_str(passwd, OPSLIMIT, MEMLIMIT);

    it('pwhash_str is does not fail', function() {	
        assert(out !== null);
        assert(out2 !== null);
        assert(!out.equals(out2), "Should generate different salts");
    });

    it('crypto_pwhash_scryptsalsa208sha256_str_needs_rehash false positive', function() {
		result = sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(out, OPSLIMIT, MEMLIMIT) 
		assert(result);
	});
		
	it('crypto_pwhash_scryptsalsa208sha256_str_needs_rehash false negative', function() {
		assert(!sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(out, OPSLIMIT, MEMLIMIT / 2));
		assert(!sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(out, OPSLIMIT / 2, MEMLIMIT));
		assert(!sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(out, OPSLIMIT, MEMLIMIT * 2));
		assert(!sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(out, OPSLIMIT * 2, MEMLIMIT));
	});

	it('crypto_pwhash_scryptsalsa208sha256_str_needs_rehash should fail with an invalid hash string', function() {
		var out3 = Buffer.alloc(out.length).fill(0);
		out.copy(out3);
		out3[0]++;
		assert(!sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(out3, OPSLIMIT, MEMLIMIT));
	});

	it('crypto_pwhash_scryptsalsa208sha256_str_verify should work', function() {
		assert(sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(out, passwd));
	});

	it('crypto_pwhash_scryptsalsa208sha256_str_verify should not work with invalid hash', function() {
		var out3 = Buffer.allocUnsafe(out.length).fill(0);
		out.copy(out3);
		out3[14]++;
		assert(!sodium.crypto_pwhash_scryptsalsa208sha256_str_verify(out3, passwd));
    });
    
	it('crypto_pwhash_scryptsalsa208sha256_str_verify should produce valid strings', function() {
    	assert(out[sodium.crypto_pwhash_scryptsalsa208sha256_STRBYTES - 1] == 0);
	});

	it('crypto_pwhash_scryptsalsa208sha256_str_needs_rehash with a small opslimit should fail', function() {
		assert(!sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash(out, 0, 0));
	});

    it('crypto_pwhash_scryptsalsa208sha256_str_needs_rehash', function() {
        assert.throws(function() {
            sodium.crypto_pwhash_scryptsalsa208sha256_str_needs_rehash
            (Buffer.from(""), OPSLIMIT, MEMLIMIT) 
        });
    });

    it('crypto_pwhash constants', function() {
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_bytes_min() > 0);
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_bytes_max() >
            sodium.crypto_pwhash_scryptsalsa208sha256_bytes_min());
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_passwd_max() >
            sodium.crypto_pwhash_scryptsalsa208sha256_passwd_min());
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_saltbytes() > 0);
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_strbytes() > 1);
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_strbytes() >
            sodium.crypto_pwhash_scryptsalsa208sha256_strprefix().length);

        assert(sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_min() > 0);
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_max() > 0);
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_min() > 0);
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_max() > 0);
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive() > 0);
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive() > 0);
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive() > 0);
        assert(sodium.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive() > 0);
        
    })
});