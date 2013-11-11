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
                'libraries': [
                        "-lsodium", "-L../libsodium/src/libsodium/.libs"
                ],
                'cflags!': [ '-fno-exceptions' ],
                'cflags_cc!': [ '-fno-exceptions' ],
                'conditions': [
                    ['OS=="mac"', {
                        'xcode_settings': {
                        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES'
                        }
                    }]
                ]
            }
      ]
}