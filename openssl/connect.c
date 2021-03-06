/**
 * The simplest SSL/TLS connection program using OpenSSL 1.1.1
 *
 * All it does is it connects to a server, establishes an SSL/TLS tunnel, sends an
 * HTTP request and reads a chunk of the reponse. There is no certificate validation
 * or verification, no hostname verification, no requirements on protocol versions or
 * cipher suites. There is no error recovery mechanism -- as an error is immediately
 * reported, the program cleans up and exists with a nonzero code.
 *
 * Observations:
 *      1.  Use SSL_{read,write} instead of BIO_{read,write}
 *      2.  Error checking is tricky, but not as inconsistent as I thought. There are
 *          three ways an OpenSSL function can fail here:
 *          a)  f() != 1        most prevalent
 *          b)  f() == NULL     when returning a pointer
 *          c)  f() <= 0        when writing or reading data
 *          Additionaly, POSIX uses its own set of conventions. For instance,
 *          socket() and connect() return -1 on error.
 *      3.  It is not used here, but OpenSSL has its own way of handling and passing
 *          error codes and messages. It is similar to standard errno, but additional
 *          care needs to be given.
 *      4.  Rudimentary certificate and hostname verification is actually easier than
 *          expected.
 *      5.  ...
 *
 * Sources:
 * - OpenSSL's own s_client app
 *      https://github.com/openssl/openssl/blob/OpenSSL_1_1_1/apps/s_client.c
 * - OpenSSL certificate pinning sample program from the OWAS wiki:
 *      https://www.owasp.org/index.php/Pinning_Cheat_Sheet#OpenSSL
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>

#define DEFAULT_HOST "example.com"
#define PORT "443"

#define BUFFER_SIZE 1024

/* Macros for easier error handling. */
#define OPENSSL_FAIL() do { \
        ret = 1; \
        ERR_print_errors_fp(stderr); \
        goto cleanup; \
    } while (0)
#define OPENSSL_CHECK(x) if ((x) != 1) { \
        OPENSSL_FAIL(); \
    }
#define CUSTOM_FAIL(error) do { \
        ret = 1; \
        fprintf(stderr, "Error: %s\n", error); \
        goto cleanup; \
    } while (0)
#define UNUSED(x) (void)(x)

#define REQUEST_TEMPLATE    \
    "GET / HTTP/1.1\r\n"    \
    "Host: %s\r\n"          \
    "Connection: close\r\n" \
    "\r\n"

int ocsp_callback(SSL *ssl, void *param) {
    UNUSED(param);

    /* Check for certificate revocation via OCSP stapling. */
    unsigned char *response_raw = NULL;
    long response_len = SSL_get_tlsext_status_ocsp_resp(ssl,
            &response_raw);
    if (response_len == -1) {
        fprintf(stderr, "Server did not send OCSP response.\n");
        /* TODO: Ideally, we should now either query the OCSP server directly or
         * try CRL if available. */
        OPENSSL_free(response_raw);
        return 1;
    }

    OCSP_RESPONSE *response = NULL;
    if ((response = d2i_OCSP_RESPONSE(NULL, (const unsigned char **)&response_raw,
                    response_len)) == NULL)
    {
        fprintf(stderr, "Could not parse OCSP response.\n");
        OPENSSL_free(response_raw);
        return 1;
    }

    /* TODO: What next? Need to get certid from server certificate, then call
     * OCSP_resp_find_status. */

    OPENSSL_free(response);

    return 1;
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
        CUSTOM_FAIL("Failed to allocate memory for request.");
    }

    /* SSL/TLS context. */
    SSL_CTX *ctx = NULL;
    /* SSL/TLS channel. */
    SSL *ssl = NULL;
    /* TCP/IP socket descriptor. */
    int sock = -1;

    /* No explicit initialisation is needed as of OpenSSL 1.1.0. */

    /* Create TLS context. Negotiate the highest version of TLS possible. */
    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        OPENSSL_FAIL();
    }

    /* Require TLS version at least 1.2. */
    OPENSSL_CHECK(SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION));

    /* Require verification of the server certificate. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 5);
    /* Use default system-wide certificate store. */
    OPENSSL_CHECK(SSL_CTX_set_default_verify_paths(ctx));
    /* Request the server to send OCSP status. */
    OPENSSL_CHECK(SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp));
    OPENSSL_CHECK(SSL_CTX_set_tlsext_status_cb(ctx, ocsp_callback));

    /* Create TCP/IP socket and connect. */
    {
        BIO_ADDRINFO *result = NULL;

        OPENSSL_CHECK(BIO_lookup_ex(hostname, PORT, BIO_LOOKUP_CLIENT, AF_UNSPEC,
                    SOCK_STREAM, IPPROTO_TCP, &result));

        const BIO_ADDRINFO *ai = result;
        while (ai != NULL) {
            sock = BIO_socket(BIO_ADDRINFO_family(ai), BIO_ADDRINFO_socktype(ai),
                    BIO_ADDRINFO_protocol(ai), 0);
            if (sock >= 0) {
                break;
            }
            ai = BIO_ADDRINFO_next(ai);
        }
        BIO_ADDRINFO_free(result);

        if (sock < 0) {
            CUSTOM_FAIL("Could not connect to the server.");
        }

        OPENSSL_CHECK(BIO_connect(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY));
    }

    /* Create TLS channel. */
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        OPENSSL_FAIL();
    }

    /* Set the host name for Server Name Indication. */
    OPENSSL_CHECK(SSL_set_tlsext_host_name(ssl, hostname));
    /* Set the host name for certificate verification. */
    OPENSSL_CHECK(SSL_set1_host(ssl, hostname));

    /* Input/output channel. */
    BIO *bio = BIO_new_socket(sock, BIO_NOCLOSE);
    if (bio == NULL) {
        OPENSSL_FAIL();
    }

    SSL_set_bio(ssl, bio, bio);

    /* Initiate TLS connection. */
    OPENSSL_CHECK(SSL_connect(ssl));

    /* Check that the server sent a certificate. */
    {
        X509 *cert = SSL_get_peer_certificate(ssl);
        if (cert == NULL) {
            CUSTOM_FAIL("Server did not send certificate -- will not connect.");
        }
        X509_free(cert);
    }
    
    /* Check if the certificate was was verified successfully. */
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        CUSTOM_FAIL("Could not verify server certificate.");
    }

    /* Send the HTTP request to the server. */
    if (SSL_write(ssl, request, strlen(request)) <= 0) {
        OPENSSL_FAIL();
    }

    /* Read the HTTP response and output it onto the standard output. */
    char buffer[BUFFER_SIZE + 1] = { 0 };
    while ((ret = SSL_read(ssl, buffer, BUFFER_SIZE)) > 0) {
        fwrite(buffer, 1, ret, stdout);
    }

    /* Check for errors during reading. */
    if (ret < 0 && ret != SSL_ERROR_ZERO_RETURN) {
        CUSTOM_FAIL("An error occurred when reading from TLS channel.");
    }

cleanup:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        /* SSL_free also cleans up the BIO. */
        SSL_free(ssl);
    }
    if (sock >= 0) {
        BIO_closesocket(sock);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }
    if (request != NULL) {
        free(request);
    }

    return ret;
}

