{
  'variables': {
        'target_arch%': '<!(node -e \"var os = require(\'os\'); console.log(os.arch());\")>'},

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
