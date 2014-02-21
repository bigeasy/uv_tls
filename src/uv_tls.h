typedef struct uv_tls_s uv_tls_t;
typedef struct uv_tls_write_s uv_tls_write_t;

typedef void (*uv_tls_write_cb)(uv_tls_write_t* req, int status);
typedef uv_buf_t (*uv_tls_alloc_cb)(uv_tls_t* tls, size_t suggested_size);
typedef void (*uv_tls_read_cb)(uv_tls_t* tls, ssize_t nread, uv_buf_t buf);

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

    uv_write_t write;

    uv_tls_write_t *writes;
    uv_tls_write_t writes_head;

    uv_tls_alloc_cb alloc_cb;
    uv_tls_read_cb read_cb;

    BIO *bio_io;
    BIO *bio_ssl;

    BIO *ssl_bio;

    boolean_t writing;

    int canary;
};

void *uv_tls_data (uv_tcp_t *tcp);
void uv_tls_connect (uv_tls_t *tls, uv_tcp_t *tcp, SSL_CTX *ssl_ctx);
void uv_tls_write (uv_tls_write_t *write, uv_tls_t* tls,
    uv_buf_t bufs[], int bufcnt, uv_tls_write_cb write_cb);
void uv_tls_read_start (uv_tls_t *tls, uv_tls_alloc_cb on_alloc, uv_tls_read_cb on_read);
