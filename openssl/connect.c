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
 *      4.  Certificate and hostname verification, again not shown, is complex,
 *          unintuitive and unpredictable.
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
#include <openssl/ssl.h>

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
    "\r\n",
    NULL
};

int main(void) {
    /* Final return value of the program. */
    int ret = 0;
    /* SSL/TLS context. */
    SSL_CTX *ctx = NULL;
    /* SSL/TLS channel. */
    SSL *ssl = NULL;
    /* TCP/IP socket descriptor. */
    int sock = -1;

    /* No explicit initialisation is needed as of OpenSSL 1.1.0. */

    /* Create an SSL/TLS context. */
    {
        /* Negotiate the highest version of TLS possible. */
        const SSL_METHOD *method = TLS_client_method();
        if (method == NULL) {
            FAIL();
        }

        /* Create TLS context. */
        ctx = SSL_CTX_new(method);
        if (ctx == NULL) {
            FAIL();
        }
    }

    /* Create TCP/IP socket and connect. */
    {
        BIO_ADDRINFO *result = NULL;

        if (BIO_lookup_ex(HOST, PORT, BIO_LOOKUP_CLIENT, AF_UNSPEC, SOCK_STREAM,
                    IPPROTO_TCP, &result) != 1)
        {
            FAIL();
        }

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
            FAIL();
        }

        if (BIO_connect(sock, BIO_ADDRINFO_address(ai), BIO_SOCK_NODELAY) != 1) {
            FAIL();
        }
    }

    /* Alternative version using POSIX sockets as spotted in the OWASP example. */
    /*
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
    */

    /* Create TLS channel. */
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        FAIL();
    }

    if (SSL_set_tlsext_host_name(ssl, HOST) != 1) {
        FAIL();
    }

    /* Input/output channel. */
    BIO *bio = BIO_new_socket(sock, BIO_NOCLOSE);
    if (bio == NULL) {
        FAIL();
    }

    SSL_set_bio(ssl, bio, bio);

    /* Initiate TLS connection. */
    if (SSL_connect(ssl) != 1) {
        FAIL();
    }

    const char **line = request_lines;
    while (*line) {
        if (SSL_write(ssl, *line, strlen(*line)) <= 0) {
            FAIL();
        }
        ++line;
    }

    char buffer[BUFFER_SIZE + 1] = { 0 };
    if (SSL_read(ssl, buffer, BUFFER_SIZE) <= 0) {
        FAIL();
    }
    printf("\x1b[34mread %zu bytes:\x1b[0m\n%s\x1b[34m###\x1b[0m\n",
            strlen(buffer), buffer);

cleanup:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        /* SSL_free also cleans up the BIO. */
        SSL_free(ssl);
    }
    if (sock >= 0) {
        BIO_closesocket(sock);
        //close(sock);
    }
    if (ctx != NULL) {
        SSL_CTX_free(ctx);
    }

    return ret;
}

