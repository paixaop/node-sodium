{
  'variables': {
    'target_arch%': '<!(node -e \"var os = require(\'os\'); console.log(os.arch());\")>'
  },
  'targets': [
    {
      'target_name': 'sodium',
      'sources': [
        './src/sodium.cc',
        './src/helpers.cc',
        './src/randombytes.cc',
        './src/crypto_pwhash.cc',
        './src/crypto_hash.cc',
        './src/crypto_hash_sha256.cc',
        './src/crypto_hash_sha512.cc',
        './src/crypto_shorthash.cc',
        './src/crypto_shorthash_siphash24.cc',
        './src/crypto_generichash.cc',
        './src/crypto_generichash_blake2b.cc'
      ],
      'include_dirs': [
        './src/include',
        './deps/build/include',
        "<!(node -e \"require('nan')\")"
      ],
      'cflags!': [ '-fno-exceptions' ],
      "conditions": [
        ['OS=="mac"', {
          "libraries": [
              '../deps/build/lib/libsodium.a'
          ],
          "variables": {
            "osx_min_version": "<!(sw_vers -productVersion | awk -F \'.\' \'{print $1 \".\" $2}\')>"
          },
          "xcode_settings": {
              "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
              "OTHER_CFLAGS": ["-arch x86_64 -O2 -g -flto -mmacosx-version-min=<(osx_min_version)"],
              "OTHER_LDFLAGS": ["-arch x86_64 -mmacosx-version-min=<(osx_min_version) -flto"]
          }
        }],
        ['OS=="win"', {
          "libraries": [
              '../deps/build/lib/libsodium.lib'
          ]
        }],
        ['OS=="linux"', {
          "libraries": [
              '../deps/build/lib/libsodium.lib'
          ]
        }]
      ]
    }
  ]
}
