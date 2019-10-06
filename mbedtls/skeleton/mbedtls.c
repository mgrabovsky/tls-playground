/**
 * Skeleton for PA193 homework #3, target mbed TLS ~ 2.13.0
 */
#include <stdio.h>
#include <stdlib.h>

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>

#define DEFAULT_HOST "example.com"
#define PORT "443"

#define REQUEST_TEMPLATE    \
    "GET / HTTP/1.1\r\n"    \
    "Host: %s\r\n"          \
    "Connection: close\r\n" \
    "\r\n"

static void fail(int error) {
    char buffer[200] = { 0 };

    mbedtls_strerror(error, buffer, sizeof(buffer));
    fprintf(stderr, "%s\n", buffer);

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

    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_config       config;
    mbedtls_ssl_context      ssl;

    /* Initialise the RNG, the network layer interface and the SSL/TLS structures. */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_config_init(&config);
    mbedtls_ssl_init(&ssl);

    /* Seed the random number generator. */
    if ((ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0) {
        fail(ret);
    }

    /* Set the RNG to be used with TLS. */
    mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &drbg);
    /* More configuration can follow... */

    if ((ret = mbedtls_ssl_setup(&ssl, &config)) != 0) {
        fail(ret);
    }

    /**
     * TODO: Continue with your code here...
     */

    mbedtls_ssl_close_notify(&ssl);

    /* Gracefully free all used resources. */
    mbedtls_ssl_config_free(&config);
    mbedtls_ssl_free(&ssl);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);

    if (request != NULL) {
        free(request);
    }

    return 0;
}

