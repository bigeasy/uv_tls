typedef struct uv_tls_s {
    void *data;

    uv_loop_t *loop;
    uv_tcp_t *tcp;
    SSL_CTX *ssl_ctx;

    SSL *ssl;
    BIO *read_bio;
    BIO *write_bio;

    uv_write_t write;

    uv_tls_buffer_t input;
    uv_tls_buffer_t output;

    int canary;
} uv_tls_t;

void *uv_tls_data (uv_tcp_t *tcp);
void uv_tls_connect (uv_tls_t *tls, uv_tcp_t *tcp, SSL_CTX *ssl_ctx);
