#include <assert.h>
#include <uv.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "uv_tls.h"

#define check(tls, err, label) \
    if (err) { \
        uv_err_t _uv_err = uv_last_error((tls)->loop); \
        fprintf(stderr, "error %s: %s\n", uv_err_name(_uv_err), uv_strerror(_uv_err)); \
        goto label; \
    }

static void write_cb (uv_write_t* write, int status)
{
    fprintf(stderr, "written\n");
}

static void uv_tls_ssl_flush_read_bio(uv_tls_t *tls);

static void uv_tls_check_write (uv_tls_t *tls)
{
    int index, err;
    uv_buf_t buf;
    uv_tls_write_t *write;
    if (!tls->writing && SSL_is_init_finished(tls->ssl) && tls->writes->next->tls) {
        write = tls->writes->next;
        index = write->index;

        if (++write->index == write->count) {
            write->next->prev = write->prev;
            write->prev->next = write->next;
        }

        fprintf(stderr, "writing: %d\n", write->bufs[0].len);
        buf = *(write->bufs + index);

        fprintf(stderr, "writing: %d\n", buf.len);
        err = SSL_write(tls->ssl, buf.base, buf.len);
        fprintf(stderr, "writing\n");

        uv_tls_ssl_flush_read_bio(tls);
    }
    return;
failure:
    return;
}

void uv_tls_write (uv_tls_write_t *write, uv_tls_t* tls,
    uv_buf_t bufs[], int bufcnt, uv_tls_write_cb write_cb)
{
    int i;
    write->application = TRUE;
    write->tls = tls;
    write->bufs = malloc(sizeof(uv_buf_t) * bufcnt);
    write->count = bufcnt;
    write->write_cb = write_cb;
    write->write.data = write;

    for (i = 0; i < bufcnt; i++) {
        write->bufs[i] = bufs[i];
    }

    write->next = tls->writes;
    write->prev = tls->writes->prev;
    write->next->prev = write->prev->next = write;

    uv_tls_check_write(tls);
}

static void uv_tls_ssl_flush_read_bio (uv_tls_t *tls)
{
    char data[1024*16];
    int bytes_read, err;
    uv_buf_t buf;

    buf.base = data;
    buf.len = sizeof(data);

    if ((bytes_read = BIO_read(tls->write_bio, data, sizeof(data))) > 0) {
        buf.len = bytes_read;
        fprintf(stderr, "x read: %d\n", bytes_read);
        err = uv_write(&tls->write, (uv_stream_t*)tls->tcp, &buf, 1, write_cb);
        fprintf(stderr, "read: %d\n", bytes_read);
        check(tls, err, fail);
    }

    fprintf(stderr, "flush\n");

    return;
fail:
    fprintf(stderr, "failed\n");
}

static int uv_tls_ssl_check_want_read (uv_tls_t *tls, int err)
{
    if (err < 0 && SSL_get_error(tls->ssl, err) == SSL_ERROR_WANT_READ) {
        uv_tls_ssl_flush_read_bio(tls);
        return 1;
    }
    return 0;
}

static void uv_tls_ssl_update (uv_tls_t* tls)
{
    char buf[1];
    int err;
    if (!SSL_is_init_finished(tls->ssl)) {
        err = SSL_connect(tls->ssl);
        uv_tls_ssl_check_want_read(tls, err);
    } else {
        // connect, check if there is encrypted data, or we need to send app data
        err = SSL_read(tls->ssl, buf, sizeof(buf));
        if (!uv_tls_ssl_check_want_read(tls, err) && err > 0) {
        }
    }
    uv_tls_check_write(tls);
}

static uv_buf_t uv_tls_alloc_cb (uv_handle_t* handle, size_t suggested_size)
{
    uv_tls_t *tls = (uv_tls_t*) handle->data;
    uv_buf_t buf;

    fprintf(stderr, "uv_tls_alloc_cb\n");
    fprintf(stderr, "uv_tls_alloc_cb canary: %#010x\n", tls->canary);

    buf.base = malloc(suggested_size);
    buf.len = suggested_size;

    return buf;
}

static void uv_tls_read_cb (uv_stream_t* stream, ssize_t nread, uv_buf_t buf)
{
    uv_tls_t *tls = (uv_tls_t*) stream->data;
    fprintf(stderr, "canary: %#010x\n", tls->canary);
    fprintf(stderr, "read: %zd\n", nread);
    BIO_write(tls->read_bio, buf.base, nread);
    uv_tls_ssl_update(tls);
}

static void uv_tls_connect_cb (uv_connect_t* connect, int status)
{
    uv_tls_t *tls = connect->data;
    int err;

    assert(tls);
    fprintf(stderr, "canary: %#010x\n", tls->canary);
    fprintf(stderr, "status: %d\n", status);
    check(tls, status, failure);
    fprintf(stderr, "status: %d\n", status);

    assert(tls->ssl_ctx);
    tls->ssl = SSL_new(tls->ssl_ctx);
    tls->read_bio = BIO_new(BIO_s_mem());
    tls->write_bio = BIO_new(BIO_s_mem());

    assert(tls->ssl);
    assert(tls->ssl && tls->read_bio && tls->write_bio);
    fprintf(stderr, "status: %d\n", status);

    SSL_set_bio(tls->ssl, tls->read_bio, tls->write_bio);
    SSL_set_connect_state(tls->ssl);

    err = SSL_do_handshake(tls->ssl);
    if (err == -1) {
        switch (SSL_get_error(tls->ssl, err)) {
        case SSL_ERROR_WANT_READ:
            fprintf(stderr, "Want read.\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            fprintf(stderr, "Want write.\n");
            break;
        }
    }

    fprintf(stderr, "Connected %d.\n", err);

    uv_tls_ssl_update(tls);

    err = uv_read_start((uv_stream_t*) tls->tcp, uv_tls_alloc_cb, uv_tls_read_cb);
    return;
failure:
    fprintf(stderr, "errored");
    return;
}

void *uv_tls_data (uv_tcp_t *tcp)
{
    uv_tls_t *tls = tcp->data;
    return tls->data;
}

void uv_tls_connect (uv_tls_t* tls, uv_tcp_t *tcp, SSL_CTX *ssl_ctx) {
    int err;

    fprintf(stderr, "hello\n");

    assert(tcp->data == NULL);
    tcp->data = tls;

    tls->writes = &tls->writes_head;
    tls->writes_head.next = &tls->writes_head;
    tls->writes_head.prev = &tls->writes_head;
    tls->writes_head.tls = NULL;

    tls->tcp = tcp;
    tls->loop = tcp->loop;
    tls->ssl_ctx = ssl_ctx;

    tls->writing = FALSE;

    tls->canary = 0xa0a0a0a0;

    tls->ssl = SSL_new(tls->ssl_ctx);
    tls->read_bio = BIO_new(BIO_s_mem());
    tls->write_bio = BIO_new(BIO_s_mem());

    assert(tls->ssl);
    assert(tls->ssl && tls->read_bio && tls->write_bio);

    SSL_set_bio(tls->ssl, tls->read_bio, tls->write_bio);
    SSL_set_connect_state(tls->ssl);

    err = SSL_do_handshake(tls->ssl);
    if (err == -1) {
        switch (SSL_get_error(tls->ssl, err)) {
        case SSL_ERROR_WANT_READ:
            fprintf(stderr, "Want read.\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            fprintf(stderr, "Want write.\n");
            break;
        }
    }

    fprintf(stderr, "Connected %d.\n", err);

    uv_tls_ssl_update(tls);

    err = uv_read_start((uv_stream_t*) tls->tcp, uv_tls_alloc_cb, uv_tls_read_cb);
    return;
failure:
    fprintf(stderr, "errored");
    return;
}
