/**
 * Skeleton for PA193 homework #3, target OpenSSL ~ 1.1.1
 */
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define HOST "www.example.com"
#define PORT "443"

const char *request_lines[] = {
    "GET / HTTP/1.1\r\n",
    "Host: " HOST "\r\n",
    "Connection: close\r\n",
    "\r\n",
    NULL
};

static void fail(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(void) {
    /* SSL/TLS context. */
    SSL_CTX *ctx = NULL;
    /* SSL/TLS channel. */
    SSL *ssl = NULL;

    /* Client connection method -- negotiates the highest version of TLS possible. */
    const SSL_METHOD *method = TLS_client_method();
    if (method == NULL) {
        fail();
    }

    /* Create TLS connection context. */
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        fail();
    }

    /* Create a TLS channel. */
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        fail();
    }

    /**
     * TODO: Continue with your code here...
     */

    /* Gracefully free all used resources. */
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }

    return 0;
}

