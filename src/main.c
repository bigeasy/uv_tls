#include<stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include<uv.h>
#include<openssl/ssl.h>
#include<openssl/bio.h>

#include "buffer.h"

#define check(program, err, label) \
    if (err) { \
        uv_err_t _uv_err = uv_last_error((program)->loop); \
        fprintf(stderr, "error %s: %s\n", uv_err_name(_uv_err), uv_strerror(_uv_err)); \
        goto label; \
    }

typedef struct {
    uint32_t flag;
    uv_loop_t *loop;
    uv_tcp_t client;
    uv_connect_t connect_req;
    uv_write_t write_req;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    BIO *read_bio;
    BIO *write_bio;
    uv_tls_buffer_t read;
    uv_tls_buffer_t write;
} test_program_t;

static void uv_tls_ssl_update (test_program_t* program);

static uv_buf_t alloc_cb (uv_handle_t* handle, size_t suggested_size)
{
    test_program_t *program = (test_program_t*) handle->data;
    uv_buf_t buf;

    fprintf(stderr, "[status] flag: %#010x\n", program->flag);

    buf.base = malloc(suggested_size);
    buf.len = suggested_size;

    return buf;
}

#define WHERE_INFO(ssl, w, flag, msg) { \
    if(w & flag) { \
      fprintf(stderr, "\t"); \
      fprintf(stderr, msg); \
      fprintf(stderr, " - %s ", SSL_state_string(ssl)); \
      fprintf(stderr, " - %s ", SSL_state_string_long(ssl)); \
      fprintf(stderr, "\n"); \
    }\
 }

static void ssl_info_callback(const SSL* ssl, int where, int ret)
{
    if(ret == 0) {
        printf("dummy_ssl_info_callback, error occured.\n");
        return;
    }
    WHERE_INFO(ssl, where, SSL_CB_LOOP, "LOOP");
    WHERE_INFO(ssl, where, SSL_CB_EXIT, "EXIT");
    WHERE_INFO(ssl, where, SSL_CB_READ, "READ");
    WHERE_INFO(ssl, where, SSL_CB_WRITE, "WRITE");
    WHERE_INFO(ssl, where, SSL_CB_ALERT, "ALERT");
    WHERE_INFO(ssl, where, SSL_CB_HANDSHAKE_DONE, "HANDSHAKE DONE");
}

static void ssl_msg_callback(
    int writep, int version, int contentType,
    const void *buf, size_t len, SSL *ssl, void *arg
) {
    fprintf(stderr, "\tMessage callback with length: %zu\n", len);
}

static int ssl_verify_callback(int ok, X509_STORE_CTX* store) {
    char buf[256];
    int err, depth;
    X509* err_cert;
    err_cert = X509_STORE_CTX_get_current_cert(store);
    err = X509_STORE_CTX_get_error(store);
    depth = X509_STORE_CTX_get_error_depth(store);
    X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

    BIO* outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
    X509_NAME* cert_name = X509_get_subject_name(err_cert);
    X509_NAME_print_ex(outbio, cert_name, 0, XN_FLAG_MULTILINE);
    BIO_free_all(outbio);
    printf("\tssl_verify_callback(), ok: %d, error: %d, depth: %d, name: %s\n", ok, err, depth, buf);

    return 1;  // We always return 1, so no verification actually
}

static void write_cb (uv_write_t* write, int status)
{
    fprintf(stderr, "written\n");
}

static void read_cb (uv_stream_t* stream, ssize_t nread, uv_buf_t buf)
{
    test_program_t *program = (test_program_t*) stream->data;
    fprintf(stderr, "read: %zd\n", nread);
    BIO_write(program->read_bio, buf.base, nread);
    uv_tls_ssl_update(program);
}

static void uv_tls_ssl_flush_read_bio (test_program_t *program)
{
    char data[1024*16];
    int bytes_read, err;
    uv_buf_t buf;

    buf.base = data;
    buf.len = sizeof(data);

    if ((bytes_read = BIO_read(program->write_bio, data, sizeof(data))) > 0) {
        fprintf(stderr, "read: %d\n", bytes_read);
        buf.len = bytes_read;
        err = uv_write(&program->write_req, (uv_stream_t*)&program->client, &buf, 1, write_cb);
        check(program, err, fail);
    }

    fprintf(stderr, "flush\n");

    return;
fail:
    fprintf(stderr, "failed\n");
}

static int uv_tls_ssl_check_want_read (test_program_t *program, int err)
{
    if (err < 0 && SSL_get_error(program->ssl, err) == SSL_ERROR_WANT_READ) {
        uv_tls_ssl_flush_read_bio(program);
        return 1;
    }
    return 0;
}

static void uv_tls_ssl_update (test_program_t* program)
{
    char buf[1];
    int err;
    if (!SSL_is_init_finished(program->ssl)) {
        err = SSL_connect(program->ssl);
        uv_tls_ssl_check_want_read(program, err);
    } else {
        // connect, check if there is encrypted data, or we need to send app data
        err = SSL_read(program->ssl, buf, sizeof(buf));
        if (!uv_tls_ssl_check_want_read(program, err) && err > 0) {
        }
    }
}

static void ping (test_program_t *program)
{
    char buffer[] = { 1, 2, 3, 4 };

    uv_tls_buffer_shift(&program->write, buffer, sizeof(buffer));
}

static void connect_cb (uv_connect_t* req, int status)
{
    int err;
    test_program_t* program = (test_program_t*) req->data;

    program->ssl = SSL_new(program->ssl_ctx);
    program->read_bio = BIO_new(BIO_s_mem());
    program->write_bio = BIO_new(BIO_s_mem());

    uv_tls_buffer_init(&program->read);
    uv_tls_buffer_init(&program->write);

    ping(program);

    SSL_set_bio(program->ssl, program->read_bio, program->write_bio);
    SSL_set_connect_state(program->ssl);

    err = SSL_do_handshake( program->ssl);
    if (err == -1) {
        switch (SSL_get_error(program->ssl, err)) {
        case SSL_ERROR_WANT_READ:
            fprintf(stderr, "Want read.\n");
            break;
        case SSL_ERROR_WANT_WRITE:
            fprintf(stderr, "Want write.\n");
            break;
        }
    }

    fprintf(stderr, "Connected %d.\n", err);

    uv_tls_ssl_update(program);

    err = uv_read_start((uv_stream_t*) &program->client, alloc_cb, read_cb);
    check(program, err, fail);

fail:

    fprintf(stderr, "todo: connect failure cleanup");
//  uv_close((uv_handle_t*) &client, close_cb);
}

int main ()
{
    struct sockaddr_in addr;
    int err;
    test_program_t program;
    BIO* bio_err;

    program.flag = 0xa0a0a0a0;

    SSL_library_init();
    SSL_load_error_strings();

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    program.ssl_ctx = SSL_CTX_new(SSLv3_client_method());
    program.ssl = NULL;

    SSL_CTX_set_options(program.ssl_ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_verify(program.ssl_ctx, SSL_VERIFY_PEER, ssl_verify_callback);
    SSL_CTX_set_info_callback(program.ssl_ctx, ssl_info_callback);
    SSL_CTX_set_msg_callback(program.ssl_ctx, ssl_msg_callback);

    program.loop = uv_loop_new();

    addr = uv_ip4_addr("127.0.0.1", 8386);

    err = uv_tcp_init(program.loop, &program.client);
    check(&program, err, fail);

    program.loop->data = &program;
    program.connect_req.data = &program;
    program.client.data = &program;

    err = uv_tcp_connect(&program.connect_req,
                         &program.client,
                         addr,
                         connect_cb);
    check(&program, err, fail);

    uv_run(program.loop, UV_RUN_DEFAULT);

    return EXIT_SUCCESS;
fail:
    return EXIT_FAILURE;
}
