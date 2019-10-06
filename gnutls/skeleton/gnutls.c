/**
 * Skeleton for PA193 homework #3, target GnuTLS ~ 3.6.4
 */
#include <stdio.h>
#include <stdlib.h>

#include <gnutls/gnutls.h>

#define HOST "www.example.com"
#define PORT "443"

const char *request_lines[] = {
    "GET / HTTP/1.1\r\n",
    "Host: " HOST "\r\n",
    "Connection: close\r\n",
    "\r\n",
    NULL
};

static void fail(int error) {
    fprintf(stderr, "%s\n", gnutls_strerror(error));
    abort();
}

int main(void)
{
    int ret = 0;
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
    gnutls_global_deinit();

    return 0;
}

