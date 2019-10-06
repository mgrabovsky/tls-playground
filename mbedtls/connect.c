/**
 * The simplest SSL/TLS connection program using mbed TLS 2.13.0
 *
 * Sources:
 * - mbed TLS tutorial:
 *      https://tls.mbed.org/kb/how-to/mbedtls-tutorial
 */
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/debug.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>

#define DEFAULT_HOST "example.com"
#define PORT "443"

#define BUFFER_SIZE 1024

/* Rudimentary error handling. */
#define MBEDTLS_FAIL(x) do { \
        char error_buffer[500] = ""; \
        mbedtls_strerror(x, error_buffer, 500); \
        fprintf(stderr, "mbed TLS error: %s\n", error_buffer); \
        ret = 1; \
        goto cleanup; \
    } while (0)
#define MBEDTLS_CHECK(x) if ((ret = (x)) != 0) { \
        MBEDTLS_FAIL(ret); \
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

    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_net_context      net;
    mbedtls_ssl_config       config;
    mbedtls_x509_crt         certs;
    mbedtls_ssl_context      ssl;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_net_init(&net);
    mbedtls_ssl_config_init(&config);
    mbedtls_x509_crt_init(&certs);
    mbedtls_ssl_init(&ssl);

    MBEDTLS_CHECK(mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0));

    /* Connect to the server via TCP. */
    MBEDTLS_CHECK(mbedtls_net_connect(&net, hostname, PORT, MBEDTLS_NET_PROTO_TCP));

    /* Use some library-provided configuration defaults. */
    MBEDTLS_CHECK(mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT));

    /* Require TLS version at least 1.2. */
    mbedtls_ssl_conf_min_version(&config, MBEDTLS_SSL_MAJOR_VERSION_3,
            MBEDTLS_SSL_MINOR_VERSION_3);

    /* Assign the RNG to the connection. */
    mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &drbg);
    /* Require verification of server certificate. */
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);

    /* Use the system certificate authorities. */
    mbedtls_x509_crt_parse_path(&certs, "/etc/ssl/certs");
    mbedtls_ssl_conf_ca_chain(&config, &certs, NULL);

    MBEDTLS_CHECK(mbedtls_ssl_setup(&ssl, &config));
    /* Set requested server hostname (SNI). */ 
    MBEDTLS_CHECK(mbedtls_ssl_set_hostname(&ssl, hostname));

    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* Explicitly perform the handshake here so that we can check for certifiacte
     * verification status. */
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
                CUSTOM_FAIL("Server certificate verification failed.");
            }
            MBEDTLS_FAIL(ret);
        }
    }

    /* TODO: Check for certificate revocation. */

    /* Send the HTTP request line by line. */
        int line_length   = strlen(request);
        int bytes_written = 0;
        /* mbedtls_ssl_write may perform partial writes -- we must check for these cases
         * and call the function again if necessary. */
        do {
            ret = mbedtls_ssl_write(&ssl, request + bytes_written, 
                    line_length - bytes_written);
            if (ret <= 0) {
                if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
                    ret != MBEDTLS_ERR_SSL_WANT_WRITE)
                {
                    MBEDTLS_FAIL(ret);
                }
            } else {
                bytes_written += ret;
            }
        } while (bytes_written < line_length);

    /* Read the HTTP response. */
    char buffer[BUFFER_SIZE + 1] = { 0 };
    while ((ret = mbedtls_ssl_read(&ssl, buffer, BUFFER_SIZE)) > 0) {
        fwrite(buffer, 1, ret, stdout);
    }

    /* Check for errors during reading. */
    if (ret < 0 && ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        MBEDTLS_FAIL(ret);
    }

cleanup:
    /* Clean up all resources. */
    mbedtls_ssl_free(&ssl);
    mbedtls_x509_crt_free(&certs);
    mbedtls_ssl_config_free(&config);
    mbedtls_net_free(&net);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    
    if (request != NULL) {
        free(request);
    }

    return ret;
}

