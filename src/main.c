#include<stdlib.h>
#include<uv.h>
#include<openssl/ssl.h>
#include<openssl/bio.h>

int main()
{
    uv_loop_new();
    SSL_library_init();

    return EXIT_SUCCESS;
}
