typedef struct uv_tls_buffer_entry_s {
    uv_buf_t buf;
    struct uv_tls_buffer_entry_s *next;
    struct uv_tls_buffer_entry_s *prev;
} uv_tls_buffer_entry_t;

typedef struct {
    uv_tls_buffer_entry_t *head;
} uv_tls_buffer_t;

void uv_tls_buffer_init (uv_tls_buffer_t* buffer);
void uv_tls_buffer_shift (uv_tls_buffer_t* buffer, char* data, size_t len);
uv_buf_t uv_tls_buffer_peek (uv_tls_buffer_t* buffer);
void uv_tls_buffer_pop (uv_tls_buffer_t* buffer);
void uv_tls_buffer_destroy (uv_tls_buffer_t* buffer);
