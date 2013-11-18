{
      'targets': [
            {
                  'target_name': 'sodium',
                  'sources': [
                        'sodium.cc',
                  ],
                  'include_dirs': [
                        './libsodium/src/libsodium/include',
                  ],
                  'cflags!': [ '-fno-exceptions' ],
                  'cflags_cc!': [ '-fno-exceptions' ],
                  'conditions': [
                        [
                              'OS=="mac"', {
                                    'xcode_settings': {
                                          'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
                                    },
                                    'libraries': [
                                          "../libsodium/src/libsodium/.libs/libsodium.a"
                                    ],
                              }
                        ],
                        [
                              'OS=="linux"', {
                                    'libraries': [
                                          "../libsodium/src/libsodium/.libs/libsodium.so"
                                    ],
                              }
                        ],
                        [
                              'OS=="win"', {
                                    'libraries': [
                                          "../libsodium/src/libsodium/.libs/libsodium.lib"
                                    ],
                              }
                        ],
                  ]
            }
      ]
}