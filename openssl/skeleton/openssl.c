/**
 * Skeleton for PA193 homework #3, target OpenSSL >= 1.1.1
 */
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#define DEFAULT_HOST "example.com"
#define PORT "443"

#define REQUEST_TEMPLATE    \
    "GET / HTTP/1.1\r\n"    \
    "Host: %s\r\n"          \
    "Connection: close\r\n" \
    "\r\n"

static void fail(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv) {
    /* Final return value of the program. */
    int ret = 0;

    /* The HTTP request string. */
    char *request = NULL;
    
    /* Name of the host we're connecting to. */
    const char *hostname = DEFAULT_HOST;

    if (argc == 2) {
        hostname = argv[1];
    } else if (argc > 2) {
        fprintf(stderr, "Invalid number of arguments. Expected zero or one.\n");
        fprintf(stderr, "Usage: %s [hostname]\n", argv[0]);
        return 1;
    }

    /* Build the request string from the template and supplied (or default) hostname.*/
    if (asprintf(&request, REQUEST_TEMPLATE, hostname) < 0) {
        request = NULL;
        fprintf(stderr, "Error: Failed to allocate memory for request.\n");
        return -1;
    }

    /* SSL/TLS context. */
    SSL_CTX *ctx = NULL;
    /* SSL/TLS channel. */
    SSL *ssl = NULL;

    /* No explicit initialisation is needed as of OpenSSL 1.1.0. */

    /* Create TLS context. Negotiate the highest version of TLS possible. */
    ctx = SSL_CTX_new(TLS_client_method());
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
        /* SSL_free also cleans up the BIO. */
        SSL_free(ssl);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
    if (request != NULL) {
        free(request);
    }

    return ret;
}

