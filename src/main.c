#include<stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include<uv.h>
#include<openssl/ssl.h>
#include<openssl/bio.h>

#include "buffer.h"
#include "uv_tls.h"

typedef struct echo_s {
    uv_loop_t *loop;
    uv_tcp_t tcp;
    uv_tls_t tls;
    SSL_CTX *ssl_ctx;
} echo_t;

static echo_t echo;

#define check(err, label) \
    if (err) { \
        uv_err_t _uv_err = uv_last_error(echo.loop); \
        fprintf(stderr, "error %s: %s\n", uv_err_name(_uv_err), uv_strerror(_uv_err)); \
        goto label; \
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
        fprintf(stderr, "dummy_ssl_info_callback, error occured.\n");
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
    fprintf(stderr, "\tssl_verify_callback(), ok: %d, error: %d, depth: %d, name: %s\n", ok, err, depth, buf);

    return 1;  // We always return 1, so no verification actually
}

static void write_cb (uv_tls_write_t *write, int status)
{
    free(write);
}

static void ping (uv_tls_t *tls)
{
    static char buffer[] = { 1, 2, 3, 4 };
    uv_buf_t buf;
    buf.base = buffer;
    buf.len = sizeof(buffer);
    fprintf(stderr, "buffer: %zu\n", buf.len);
    uv_tls_write_t *write = malloc(sizeof (uv_tls_write_t));

    uv_tls_write(write, tls, &buf, 1, write_cb);
 //   uv_tls_buffer_shift(&program->write, buffer, sizeof(buffer));
}

static void echo_on_read (uv_tls_t* tls, ssize_t nread, uv_buf_t buf)
{
    uint32_t value = *(uint32_t*)buf.base;
    fprintf(stderr, "application read: %#010x\n", value);
    ping(tls);
}

static uv_buf_t echo_on_alloc (uv_tls_t* tls, size_t suggested_size)
{
    uv_buf_t buf;

    fprintf(stderr, "echo_on_alloc\n");

    buf.base = malloc(suggested_size);
    buf.len = suggested_size;

    return buf;
}

void echo_connect_cb (uv_connect_t* connect, int status)
{
    int err;
    check(status, failure);
    fprintf(stderr, "status: %d\n", status);
    uv_tls_connect(&echo.tls, &echo.tcp, echo.ssl_ctx);
    uv_tls_read_start(&echo.tls, echo_on_alloc, echo_on_read);

    ping(&echo.tls);

    //int err;
    return;
failure:
    return;
}

int main ()
{
    struct sockaddr_in addr;
    int err;
    uv_connect_t connect;
    BIO* bio_err;

    SSL_library_init();
    SSL_load_error_strings();

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    echo.ssl_ctx = SSL_CTX_new(SSLv3_client_method());

    SSL_CTX_set_options(echo.ssl_ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_verify(echo.ssl_ctx, SSL_VERIFY_PEER, ssl_verify_callback);
    SSL_CTX_set_info_callback(echo.ssl_ctx, ssl_info_callback);
    SSL_CTX_set_msg_callback(echo.ssl_ctx, ssl_msg_callback);

    echo.loop = uv_loop_new();

    addr = uv_ip4_addr("127.0.0.1", 8386);

    err = uv_tcp_init(echo.loop, &echo.tcp);
    check(err, failure);

    err = uv_tcp_connect(&connect, &echo.tcp, addr, echo_connect_cb);
    check(err, failure);

    err = uv_run(echo.loop, UV_RUN_DEFAULT);
    check(err, failure);

    return EXIT_SUCCESS;
failure:
    return EXIT_FAILURE;
}
