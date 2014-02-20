#include<stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include<uv.h>
#include<openssl/ssl.h>
#include<openssl/bio.h>
#include<ringbuffer.h>

#define check(program, err, label) \
    if (err) { \
        uv_err_t _uv_err = uv_last_error((program)->loop); \
        fprintf(stderr, "error %s: %s\n", uv_err_name(_uv_err), uv_strerror(_uv_err)); \
        goto label; \
    }

typedef struct {
    uv_loop_t* loop;
    uv_tcp_t client;
    uv_connect_t connect_req;
} test_program_t;

static uv_buf_t alloc_cb (uv_handle_t* handle, size_t suggested_size)
{
    uv_buf_t buf;
    buf.base = NULL;
    buf.len = 0;
    return buf;
}
static void read_cb (uv_stream_t* stream, ssize_t nread, uv_buf_t buf)
{
}

static void connect_cb (uv_connect_t* req, int status)
{
    int err;
    test_program_t* program = (test_program_t*) req->data;

    fprintf(stderr, "Connected.\n");

    exit(1);

    err = uv_read_start((uv_stream_t*) &program->client, alloc_cb, read_cb);
    check(program, err, fail);

    return;

fail:

    fprintf(stderr, "todo: connect failure cleanup");
//  uv_close((uv_handle_t*) &client, close_cb);
}

int main ()
{
    struct sockaddr_in addr;
    int err;
    test_program_t program;
    ringbuffer in;

    ringbuffer_init(&in);


    SSL_library_init();

    program.loop = uv_loop_new();

    addr = uv_ip4_addr("127.0.0.1", 8386);

    err = uv_tcp_init(program.loop, &program.client);
    check(&program, err, fail);

    program.loop->data = &program;
    program.connect_req.data = &program;

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
