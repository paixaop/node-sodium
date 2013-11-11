cmd_Release/obj.target/sodium/sodium.o := c++ '-D_DARWIN_USE_64_BIT_INODE=1' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-DBUILDING_NODE_EXTENSION' -I/Users/bmf/.node-gyp/0.10.20/src -I/Users/bmf/.node-gyp/0.10.20/deps/uv/include -I/Users/bmf/.node-gyp/0.10.20/deps/v8/include -I../libsodium/src/libsodium/include  -Os -gdwarf-2 -mmacosx-version-min=10.5 -arch x86_64 -Wall -Wendif-labels -W -Wno-unused-parameter -fno-rtti -fno-threadsafe-statics -fno-strict-aliasing -MMD -MF ./Release/.deps/Release/obj.target/sodium/sodium.o.d.raw  -c -o Release/obj.target/sodium/sodium.o ../sodium.cc
Release/obj.target/sodium/sodium.o: ../sodium.cc \
  /Users/bmf/.node-gyp/0.10.20/src/node.h \
  /Users/bmf/.node-gyp/0.10.20/deps/uv/include/uv.h \
  /Users/bmf/.node-gyp/0.10.20/deps/uv/include/uv-private/uv-unix.h \
  /Users/bmf/.node-gyp/0.10.20/deps/uv/include/uv-private/ngx-queue.h \
  /Users/bmf/.node-gyp/0.10.20/deps/uv/include/uv-private/uv-darwin.h \
  /Users/bmf/.node-gyp/0.10.20/deps/v8/include/v8.h \
  /Users/bmf/.node-gyp/0.10.20/deps/v8/include/v8stdint.h \
  /Users/bmf/.node-gyp/0.10.20/src/node_object_wrap.h \
  /Users/bmf/.node-gyp/0.10.20/src/node_buffer.h \
  ../libsodium/src/libsodium/include/sodium.h \
  ../libsodium/src/libsodium/include/sodium/core.h \
  ../libsodium/src/libsodium/include/sodium/export.h \
  ../libsodium/src/libsodium/include/sodium/crypto_auth.h \
  ../libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha512256.h \
  ../libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha256.h \
  ../libsodium/src/libsodium/include/sodium/crypto_box.h \
  ../libsodium/src/libsodium/include/sodium/crypto_box_curve25519xsalsa20poly1305.h \
  ../libsodium/src/libsodium/include/sodium/crypto_core_hsalsa20.h \
  ../libsodium/src/libsodium/include/sodium/crypto_core_salsa20.h \
  ../libsodium/src/libsodium/include/sodium/crypto_core_salsa2012.h \
  ../libsodium/src/libsodium/include/sodium/crypto_core_salsa208.h \
  ../libsodium/src/libsodium/include/sodium/crypto_generichash.h \
  ../libsodium/src/libsodium/include/sodium/crypto_generichash_blake2b.h \
  ../libsodium/src/libsodium/include/sodium/crypto_hash.h \
  ../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h \
  ../libsodium/src/libsodium/include/sodium/crypto_hash_sha256.h \
  ../libsodium/src/libsodium/include/sodium/crypto_hashblocks_sha256.h \
  ../libsodium/src/libsodium/include/sodium/crypto_hashblocks_sha512.h \
  ../libsodium/src/libsodium/include/sodium/crypto_onetimeauth.h \
  ../libsodium/src/libsodium/include/sodium/crypto_onetimeauth_poly1305.h \
  ../libsodium/src/libsodium/include/sodium/crypto_scalarmult.h \
  ../libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h \
  ../libsodium/src/libsodium/include/sodium/crypto_secretbox.h \
  ../libsodium/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h \
  ../libsodium/src/libsodium/include/sodium/crypto_shorthash.h \
  ../libsodium/src/libsodium/include/sodium/crypto_shorthash_siphash24.h \
  ../libsodium/src/libsodium/include/sodium/crypto_sign.h \
  ../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h \
  ../libsodium/src/libsodium/include/sodium/crypto_sign_edwards25519sha512batch.h \
  ../libsodium/src/libsodium/include/sodium/crypto_stream.h \
  ../libsodium/src/libsodium/include/sodium/crypto_stream_xsalsa20.h \
  ../libsodium/src/libsodium/include/sodium/crypto_stream_aes128ctr.h \
  ../libsodium/src/libsodium/include/sodium/crypto_stream_aes256estream.h \
  ../libsodium/src/libsodium/include/sodium/crypto_stream_salsa20.h \
  ../libsodium/src/libsodium/include/sodium/crypto_stream_salsa2012.h \
  ../libsodium/src/libsodium/include/sodium/crypto_stream_salsa208.h \
  ../libsodium/src/libsodium/include/sodium/crypto_verify_16.h \
  ../libsodium/src/libsodium/include/sodium/crypto_verify_32.h \
  ../libsodium/src/libsodium/include/sodium/randombytes.h \
  ../libsodium/src/libsodium/include/sodium/randombytes_salsa20_random.h \
  ../libsodium/src/libsodium/include/sodium/randombytes_sysrandom.h \
  ../libsodium/src/libsodium/include/sodium/utils.h \
  ../libsodium/src/libsodium/include/sodium/version.h
../sodium.cc:
/Users/bmf/.node-gyp/0.10.20/src/node.h:
/Users/bmf/.node-gyp/0.10.20/deps/uv/include/uv.h:
/Users/bmf/.node-gyp/0.10.20/deps/uv/include/uv-private/uv-unix.h:
/Users/bmf/.node-gyp/0.10.20/deps/uv/include/uv-private/ngx-queue.h:
/Users/bmf/.node-gyp/0.10.20/deps/uv/include/uv-private/uv-darwin.h:
/Users/bmf/.node-gyp/0.10.20/deps/v8/include/v8.h:
/Users/bmf/.node-gyp/0.10.20/deps/v8/include/v8stdint.h:
/Users/bmf/.node-gyp/0.10.20/src/node_object_wrap.h:
/Users/bmf/.node-gyp/0.10.20/src/node_buffer.h:
../libsodium/src/libsodium/include/sodium.h:
../libsodium/src/libsodium/include/sodium/core.h:
../libsodium/src/libsodium/include/sodium/export.h:
../libsodium/src/libsodium/include/sodium/crypto_auth.h:
../libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha512256.h:
../libsodium/src/libsodium/include/sodium/crypto_auth_hmacsha256.h:
../libsodium/src/libsodium/include/sodium/crypto_box.h:
../libsodium/src/libsodium/include/sodium/crypto_box_curve25519xsalsa20poly1305.h:
../libsodium/src/libsodium/include/sodium/crypto_core_hsalsa20.h:
../libsodium/src/libsodium/include/sodium/crypto_core_salsa20.h:
../libsodium/src/libsodium/include/sodium/crypto_core_salsa2012.h:
../libsodium/src/libsodium/include/sodium/crypto_core_salsa208.h:
../libsodium/src/libsodium/include/sodium/crypto_generichash.h:
../libsodium/src/libsodium/include/sodium/crypto_generichash_blake2b.h:
../libsodium/src/libsodium/include/sodium/crypto_hash.h:
../libsodium/src/libsodium/include/sodium/crypto_hash_sha512.h:
../libsodium/src/libsodium/include/sodium/crypto_hash_sha256.h:
../libsodium/src/libsodium/include/sodium/crypto_hashblocks_sha256.h:
../libsodium/src/libsodium/include/sodium/crypto_hashblocks_sha512.h:
../libsodium/src/libsodium/include/sodium/crypto_onetimeauth.h:
../libsodium/src/libsodium/include/sodium/crypto_onetimeauth_poly1305.h:
../libsodium/src/libsodium/include/sodium/crypto_scalarmult.h:
../libsodium/src/libsodium/include/sodium/crypto_scalarmult_curve25519.h:
../libsodium/src/libsodium/include/sodium/crypto_secretbox.h:
../libsodium/src/libsodium/include/sodium/crypto_secretbox_xsalsa20poly1305.h:
../libsodium/src/libsodium/include/sodium/crypto_shorthash.h:
../libsodium/src/libsodium/include/sodium/crypto_shorthash_siphash24.h:
../libsodium/src/libsodium/include/sodium/crypto_sign.h:
../libsodium/src/libsodium/include/sodium/crypto_sign_ed25519.h:
../libsodium/src/libsodium/include/sodium/crypto_sign_edwards25519sha512batch.h:
../libsodium/src/libsodium/include/sodium/crypto_stream.h:
../libsodium/src/libsodium/include/sodium/crypto_stream_xsalsa20.h:
../libsodium/src/libsodium/include/sodium/crypto_stream_aes128ctr.h:
../libsodium/src/libsodium/include/sodium/crypto_stream_aes256estream.h:
../libsodium/src/libsodium/include/sodium/crypto_stream_salsa20.h:
../libsodium/src/libsodium/include/sodium/crypto_stream_salsa2012.h:
../libsodium/src/libsodium/include/sodium/crypto_stream_salsa208.h:
../libsodium/src/libsodium/include/sodium/crypto_verify_16.h:
../libsodium/src/libsodium/include/sodium/crypto_verify_32.h:
../libsodium/src/libsodium/include/sodium/randombytes.h:
../libsodium/src/libsodium/include/sodium/randombytes_salsa20_random.h:
../libsodium/src/libsodium/include/sodium/randombytes_sysrandom.h:
../libsodium/src/libsodium/include/sodium/utils.h:
../libsodium/src/libsodium/include/sodium/version.h:
