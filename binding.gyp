{
  'variables': { 'target_arch%': 'ia32', 'naclversion': '0.4.5' },

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
                       './deps/libsodium-<(naclversion)/src/libsodium/include'
                  ],
                  'cflags!': [ '-fno-exceptions' ],
                  
            }
      ]
}
