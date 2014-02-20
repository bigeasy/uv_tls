{
    "includes": [
        "common.gypi",
        "local.gypi"
    ],
    "targets": [
        {
            "target_name": "uv_tls",
            "product_name": "uv_tls",
            "type": "static_library",
            "dependencies": [
                "deps/ringbuffer/ringbuffer.gyp:ringbuffer"
            ],
            "sources": [
                "./src/uv_tls.c"
            ],
            "include_dirs": [
                "include",
                "deps/ringbuffer"
            ],
            'direct_dependent_settings': {
              'include_dirs': [ 'include/' ],
            }
        },
        {
            "target_name": "uv_tls_test",
            "type": "executable",
            "sources": [
                "./src/main.c",
                "./src/buffer.c"
            ],
            "include_dirs": [
                "include",
                "deps/ringbuffer"
            ],
            "dependencies": [
                "uv_tls"
            ]
        }
    ]
}
