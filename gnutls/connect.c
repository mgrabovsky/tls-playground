/**
 * The simplest SSL/TLS connection program using GnuTLS 3.5.19
 *
 * Contains X.509 auth and basic certificate verification.
 *
 * Sources:
 * - GnuTLS's own examples, in particular ex-client-{anon,psk,x509}.c
 *      https://github.com/gnutls/gnutls/tree/gnutls_3_5_19/doc/examples
 *
 * Observations:
 *      1.  Easier error checking than OpenSSL -- all functions return negative
 *          values on error.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gnutls/gnutls.h>

#define HOST "www.example.com"
#define PORT "443"

#define BUFFER_SIZE 1024

/* Rudimentary error handling -- just report where it occurred and bail. */
#define FAIL() do { \
        fprintf(stderr, "Error on line %d.\n", __LINE__); \
        ret = 1; \
        goto cleanup; \
    } while (0)

const char *request_lines[] = {
    "GET / HTTP/1.1\r\n",
    "Host: " HOST "\r\n",
    "Connection: close\r\n",
    "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:63.0) Gecko/20100101 Firefox/63.0\r\n",
    "\r\n",
    NULL
};

int main(void)
{
    int ret  = 0;
    int sock = -1;
    gnutls_session_t session = NULL;
    gnutls_certificate_credentials_t creds = NULL;

    if (gnutls_global_init() < 0) {
        FAIL();
    }

    /* Initialize the SSL/TLS channel. */
    if (gnutls_init(&session, GNUTLS_CLIENT) < 0) {
        FAIL();
    }
    
    /* Set requested server name for virtualized servers. */
    if (gnutls_server_name_set(session, GNUTLS_NAME_DNS, HOST, strlen(HOST)) < 0) {
        FAIL();
    }

    if (gnutls_certificate_allocate_credentials(&creds) < 0) {
        FAIL();
    }

    if (gnutls_certificate_set_x509_system_trust(creds) < 0) {
        FAIL();
    }

    if (gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds) < 0) {
        FAIL();
    }

    gnutls_session_set_verify_cert(session, HOST, 0);

    /* Set default cipher suite priorities. */
    if (gnutls_set_default_priority(session) < 0) {
        FAIL();
    }

    /* Connect to the server. */
    {
        struct addrinfo hints = { 0 };
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags    = AI_ADDRCONFIG | AI_NUMERICSERV;
        hints.ai_protocol = IPPROTO_TCP;

        struct addrinfo *result = NULL;

        if (getaddrinfo(HOST, PORT, &hints, &result) != 0 ||
                result == NULL)
        {
            FAIL();
        }

        struct addrinfo *rr = result;
        while (rr != NULL) {
            sock = socket(rr->ai_family, rr->ai_socktype, rr->ai_protocol);
            if (sock >= 0) {
                break;
            }
            rr = rr->ai_next;
        }

        if (sock < 0) {
            FAIL();
        }

        if (connect(sock, rr->ai_addr, rr->ai_addrlen) != 0) {
            FAIL();
        }
    }

    /* Connect the socket and TLS channel. */
    gnutls_transport_set_int(session, sock);
    /* Most likely not necessary. */
    //gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    /* Attempt the TLS handshake. Some non-fatal errors are expected during the
     * process. We'll just ignore these and try again. */
    do {
        ret = gnutls_handshake(session);
    } while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

    if (ret < 0) {
        gnutls_perror(ret);
        if (gnutls_error_is_fatal(ret))
            FAIL();
    }

    const char **line = request_lines;
    while (*line) {
        if (gnutls_record_send(session, *line, strlen(*line)) <= 0) {
            FAIL();
        }
        ++line;
    }

    char buffer[BUFFER_SIZE + 1] = { 0 };
    if (gnutls_record_recv(session, buffer, BUFFER_SIZE) <= 0) {
        FAIL();
    }
    printf("\x1b[34mread %zu bytes:\x1b[0m\n%s\x1b[34m###\x1b[0m\n",
            strlen(buffer), buffer);

    if (gnutls_bye(session, GNUTLS_SHUT_RDWR) < 0) {
        FAIL();
    }

cleanup:
    if (sock >= 0) {
        close(sock);
    }
    if (creds != NULL) {
        gnutls_certificate_free_credentials(creds);
    }
    if (session != NULL) {
        gnutls_deinit(session);
    }
    gnutls_global_deinit();

    return 0;
}

