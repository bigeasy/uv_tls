typedef struct uv_tls_s uv_tls_t;
typedef struct uv_tls_write_s uv_tls_write_t;

typedef void (*uv_tls_write_cb)(uv_tls_write_t* req, int status);

struct uv_tls_write_s {
    void *data;
    uv_write_t write;
    uv_tls_t *tls;
    uv_buf_t *bufs;
    int index;
    int count;
    uv_tls_write_cb write_cb;
    int application;
    uv_tls_write_t *next;
    uv_tls_write_t *prev;
};

struct uv_tls_s {
    void *data;

    uv_loop_t *loop;
    uv_tcp_t *tcp;
    SSL_CTX *ssl_ctx;

    SSL *ssl;
    BIO *read_bio;
    BIO *write_bio;

    uv_write_t write;

    uv_tls_write_t *writes;
    uv_tls_write_t writes_head;

    boolean_t writing;

    int canary;
};

void *uv_tls_data (uv_tcp_t *tcp);
void uv_tls_connect (uv_tls_t *tls, uv_tcp_t *tcp, SSL_CTX *ssl_ctx);
void uv_tls_write (uv_tls_write_t *write, uv_tls_t* tls,
    uv_buf_t bufs[], int bufcnt, uv_tls_write_cb write_cb);
