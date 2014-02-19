{
    "includes": [
        "common.gypi"
    ],
    "targets": [
        {
            "target_name": "uv_tls",
            "product_name": "uv_tls",
            "type": "static_library",
            "sources": [
                "./src/uv_tls.c"
            ],
            "include_dirs": [
                "include"
            ],
            'direct_dependent_settings': {
              'include_dirs': [ 'include/' ],
            }
        },
        {
            "target_name": "uv_tls_test",
            "type": "executable",
            "sources": [
                "./src/main.c"
            ],
            "include_dirs": [
                "include"
            ],
            "dependencies": [
                "uv_tls"
            ]
        }
    ]
}
