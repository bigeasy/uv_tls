#include<stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include<uv.h>
#include<openssl/ssl.h>
#include<openssl/bio.h>

#include "buffer.h"
#include "uv_tls.h"

#define check(program, err, label) \
    if (err) { \
        uv_err_t _uv_err = uv_last_error(loop); \
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

static void ping ()
{
//    char buffer[] = { 1, 2, 3, 4 };

 //   uv_tls_buffer_shift(&program->write, buffer, sizeof(buffer));
}


void echo_connect_cb (uv_connect_t* connect, int status) {
}

int main ()
{
    struct sockaddr_in addr;
    int err;
    uv_connect_t connect;
    uv_loop_t *loop;
    BIO* bio_err;
    uv_tls_t tls;

    SSL_library_init();
    SSL_load_error_strings();

    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    tls.ssl_ctx = SSL_CTX_new(SSLv3_client_method());

    SSL_CTX_set_options(tls.ssl_ctx, SSL_OP_NO_SSLv2);
    SSL_CTX_set_verify(tls.ssl_ctx, SSL_VERIFY_PEER, ssl_verify_callback);
    SSL_CTX_set_info_callback(tls.ssl_ctx, ssl_info_callback);
    SSL_CTX_set_msg_callback(tls.ssl_ctx, ssl_msg_callback);

    loop = uv_loop_new();

    uv_tls_init(&tls);

    addr = uv_ip4_addr("127.0.0.1", 8386);

    err = uv_tcp_init(loop, &tls.tcp);
    check(loop, err, fail);

    uv_tls_connect(&connect, &tls, addr, echo_connect_cb);
    check(loop, err, fail);

    uv_run(loop, UV_RUN_DEFAULT);

    return EXIT_SUCCESS;
fail:
    return EXIT_FAILURE;
}
