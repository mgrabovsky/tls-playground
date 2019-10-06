/**
 * Skeleton for PA193 homework #3, target GnuTLS ~ 3.6.4
 */
#include <stdio.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>

#define DEFAULT_HOST "example.com"
#define PORT "443"

#define REQUEST_TEMPLATE    \
    "GET / HTTP/1.1\r\n"    \
    "Host: %s\r\n"          \
    "Connection: close\r\n" \
    "\r\n"

static void fail(int error) {
    fprintf(stderr, "%s\n", gnutls_strerror(error));
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

    gnutls_session_t session = NULL;

    if ((ret = gnutls_global_init()) < 0) {
        fail(ret);
    }

    /* Initialize the SSL/TLS channel. */
    if ((ret = gnutls_init(&session, GNUTLS_CLIENT)) < 0) {
        fail(ret);
    }

    /**
     * TODO: Continue with your code here...
     */

    /* Free used resources. */
    if (session != NULL) {
        gnutls_deinit(session);
    }
    if (request != NULL) {
        free(request);
    }
    gnutls_global_deinit();

    return 0;
}

