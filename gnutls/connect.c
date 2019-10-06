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
#include <gnutls/ocsp.h>

#define DEFAULT_HOST "example.com"
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

#define REQUEST_TEMPLATE    \
    "GET / HTTP/1.1\r\n"    \
    "Host: %s\r\n"          \
    "Connection: close\r\n" \
    "\r\n"


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

    /* Build the request string from the template and supplied (or default) hostname. */
    if (asprintf(&request, REQUEST_TEMPLATE, hostname) < 0) {
        request = NULL;
        CUSTOM_FAIL("Failed to allocate memory for request.");
    }

    /* TCP/IP socket descriptor. */
    int sock = -1;
    
    gnutls_session_t session = NULL;
    gnutls_certificate_credentials_t creds = NULL;

    GNUTLS_CHECK(gnutls_global_init());

    /* Initialize the SSL/TLS channel. */
    GNUTLS_CHECK(gnutls_init(&session, GNUTLS_CLIENT));
    
    /* Set requested server name for virtualized servers (SNI). */
    GNUTLS_CHECK(gnutls_server_name_set(session, GNUTLS_NAME_DNS, hostname, strlen(hostname)));

    /* Verify server certificate with default certificate authorities. */
    GNUTLS_CHECK(gnutls_certificate_allocate_credentials(&creds));
    GNUTLS_CHECK(gnutls_certificate_set_x509_system_trust(creds));
    GNUTLS_CHECK(gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, creds));
    gnutls_session_set_verify_cert(session, hostname, 0);
    /* Request an OCSP response from the server (OCSP stapling). (Is this default?) */
    GNUTLS_CHECK(gnutls_ocsp_status_request_enable_client(session, NULL, 0, NULL));

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

        if (getaddrinfo(hostname, PORT, &hints, &result) != 0 ||
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

    /* Parse stapled OCSP response if available. */
    gnutls_datum_t ocsp_response_raw = { 0 };
    if ((ret = gnutls_ocsp_status_request_get(session, &ocsp_response_raw)) != 0) {
        if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
            fprintf(stderr, "Server did not send OCSP response.\n");
            /* TODO: Ideally, we should now either query the OCSP server directly or
             * try CRL if available. */
        } else {
            GNUTLS_FAIL(ret);
        }
    } else {
        gnutls_ocsp_resp_t ocsp_response = NULL;
        GNUTLS_CHECK(gnutls_ocsp_resp_init(&ocsp_response));
        GNUTLS_CHECK(gnutls_ocsp_resp_import(ocsp_response, &ocsp_response_raw));

        gnutls_ocsp_cert_status_t status;
        GNUTLS_CHECK(gnutls_ocsp_resp_get_single(ocsp_response, 0, NULL, NULL, NULL,
                    NULL, &status, NULL, NULL, NULL, NULL));

        if (status == GNUTLS_OCSP_CERT_GOOD) {
            fprintf(stderr, "OCSP status good.\n");
        } else if (status == GNUTLS_OCSP_CERT_REVOKED) {
            fprintf(stderr, "Certificate is revoked according to stapled OCSP.\n");
        } else {
            fprintf(stderr, "Unknown OCSP status.\n");
        }

        gnutls_ocsp_resp_deinit(ocsp_response);
    }

    GNUTLS_CHECK(gnutls_record_send(session, request, strlen(request)));

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
    if (request != NULL) {
        free(request);
    }
    gnutls_global_deinit();

    return 0;
}

