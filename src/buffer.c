#include <stdlib.h>
#include <uv.h>

#include "buffer.h"

void uv_tls_buffer_init (uv_tls_buffer_t* buffer) {
    buffer->head = malloc(sizeof (uv_tls_buffer_entry_t));
    buffer->head->buf.len = 0;
    buffer->head->buf.base = NULL;
    buffer->head->next = buffer->head;
    buffer->head->prev = buffer->head;
}

void uv_tls_buffer_destroy (uv_tls_buffer_t* buffer) {
    uv_tls_buffer_entry_t* iterator = buffer->head, *outgoing;
    iterator->prev->next = NULL;
    while (iterator) {
        outgoing = iterator;
        iterator = iterator->next;
        free(outgoing);
    }
}

void uv_tls_buffer_shift (uv_tls_buffer_t* buffer, char* data, size_t len) {
    uv_tls_buffer_entry_t *node = malloc(sizeof (uv_tls_buffer_entry_t));
    node->buf.len = len;
    node->buf.base = malloc(len);
    node->next = buffer->head;
    node->prev = buffer->head->prev;
    node->next->prev = node->prev->next = node;
}

uv_buf_t uv_tls_buffer_peek (uv_tls_buffer_t* buffer) {
    return buffer->head->buf;
}

void uv_tls_buffer_pop (uv_tls_buffer_t* buffer) {
}
