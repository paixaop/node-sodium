{
  'variables': { 'target_arch%': 'ia32'},

        'targets': [
            {
                  'target_name': 'sodium',
                  'sources': [
                        'sodium.cc',
                  ],
                  "dependencies": [
                        "<(module_root_dir)/deps/libsodium.gyp:libsodium"
                  ],
                  'include_dirs': [
                       './deps/libsodium/src/libsodium/include',
                       "<!(node -e \"require('nan')\")"
                  ],
                  'cflags!': [ '-fno-exceptions' ],
                  
            }
      ]
}
