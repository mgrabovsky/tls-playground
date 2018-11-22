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

/* Rudimentary error handling. */
#define GNUTLS_FAIL(x) do { \
        gnutls_perror(x); \
        ret = 1; \
        goto cleanup; \
    } while (0)
#define GNUTLS_CHECK(x) if ((ret = (x)) < 0) { \
        GNUTLS_FAIL(ret); \
    }
#define CUSTOM_FAIL(error) do { \
        ret = 1; \
        fprintf(stderr, "Error: %s\n", error); \
        goto cleanup; \
    } while (0)

const char *request_lines[] = {
    "GET / HTTP/1.1\r\n",
    "Host: " HOST "\r\n",
    "Connection: close\r\n",
    "\r\n",
    NULL
};

int main(void)
{
    int ret  = 0;
    int sock = -1;
    gnutls_session_t session = NULL;
    gnutls_certificate_credentials_t creds = NULL;

    GNUTLS_CHECK(gnutls_global_init());

    /* Initialize the SSL/TLS channel. */
    GNUTLS_CHECK(gnutls_init(&session, GNUTLS_CLIENT));
    
    /* Set requested server name for virtualized servers (SNI). */
    GNUTLS_CHECK(gnutls_server_name_set(session, GNUTLS_NAME_DNS, HOST, strlen(HOST)));

    /* Verify server certificate with default certificate authorities. */
    GNUTLS_CHECK(gnutls_certificate_allocate_credentials(&creds));
    GNUTLS_CHECK(gnutls_certificate_set_x509_system_trust(creds));
    GNUTLS_CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds));
    gnutls_session_set_verify_cert(session, HOST, 0);

    /* Set default cipher suite priorities. */
    GNUTLS_CHECK(gnutls_set_default_priority(session));

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
            CUSTOM_FAIL("Could not connect to the server.");
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
            CUSTOM_FAIL("Could not connect to the server.");
        }

        if (connect(sock, rr->ai_addr, rr->ai_addrlen) != 0) {
            CUSTOM_FAIL("Could not connect to the server.");
        }
    }

    /* Connect the socket and TLS channel. */
    gnutls_transport_set_int(session, sock);
    /* Set default timeout for the handshake. */
    gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    /* Attempt the TLS handshake. Some non-fatal errors are expected during the
     * process. We'll just ignore these and try again. */
    do {
        ret = gnutls_handshake(session);
    } while (ret < 0 && !gnutls_error_is_fatal(ret));

    if (ret < 0) {
        /* Print the specific error which occurred during certificate verification. */
        if (ret == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR) {
            gnutls_certificate_type_t cert_type = gnutls_certificate_type_get(session);
            unsigned status = gnutls_session_get_verify_cert_status(session);
            gnutls_datum_t out = { 0 };
            gnutls_certificate_verification_status_print(status, cert_type, &out, 0);
            fprintf(stderr, "Certificate verification failed: %s\n", out.data);
            gnutls_free(out.data);
        }
        GNUTLS_FAIL(ret);
    }

    /* Beware: Unusual return value. */
    if (gnutls_ocsp_status_request_is_checked(session, 0) != 0) {
        fprintf(stderr, "OCSP status response valid.\n");
    } else {
        fprintf(stderr, "Server sent no OCSP status or it was invalid.\n");
    }

    const char **line = request_lines;
    while (*line) {
        GNUTLS_CHECK(gnutls_record_send(session, *line, strlen(*line)));
        ++line;
    }

    /* Read the HTTP response and output it onto the standard output. */
    char buffer[BUFFER_SIZE + 1] = { 0 };
    while ((ret = gnutls_record_recv(session, buffer, BUFFER_SIZE)) > 0) {
        fwrite(buffer, 1, ret, stdout);
    }

    if (ret < 0) {
        GNUTLS_FAIL(ret);
    }

    GNUTLS_CHECK(gnutls_bye(session, GNUTLS_SHUT_RDWR) < 0);

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

