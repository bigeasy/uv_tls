typedef struct uv_tls_sub_s {
    uv_connect_t *connect;
} uv_tls_sub_t;

typedef struct uv_tls_s {
    void *data;
    uv_loop_t *loop;
    SSL_CTX *ssl_ctx;
    uv_tcp_t tcp;
    uv_write_t write;
    uv_connect_t connect;
    uv_tls_sub_t sub;
    SSL *ssl;
    BIO *read_bio;
    BIO *write_bio;
    uv_tls_buffer_t input;
    uv_tls_buffer_t output;
    int canary;
} uv_tls_t;

void uv_tls_init(uv_tls_t *tls);
void uv_tls_connect (uv_connect_t* connect, uv_tls_t* tls,
    struct sockaddr_in addr, uv_connect_cb connect_cb);
