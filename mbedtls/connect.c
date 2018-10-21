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
#include <mbedtls/net.h>
#include <mbedtls/ssl.h>

#define HOST "www.example.com"
#define PORT "443"

#define GET_REQUEST \
    "GET / HTTP/1.1\r\n" \
    "Host: www.example.com\r\n" \
    "Connection: close\r\n" \
    "\r\n"

/* Rudimentary error handling -- just report where it occurred and bail. */
#define FAIL() do { \
        fprintf(stderr, "Error on line %d.\n", __LINE__); \
        ret = 1; \
        goto cleanup; \
    } while (0)

int main(void) {
    int           ret,
                  len;
    unsigned char buf[1024];

    mbedtls_net_context      net;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_context      ssl;
    mbedtls_ssl_config       config;

    mbedtls_net_init(&net);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);

    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        FAIL();
    }

    /*
     * Start the connection
     */
    printf("\n  . Connecting to tcp/%s/%s...", HOST, PORT);
    fflush(stdout);

    if (mbedtls_net_connect(&net, HOST, PORT, MBEDTLS_NET_PROTO_TCP) != 0) {
        FAIL();
    }

    printf(" ok\n");

    if (mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0)
    {
        FAIL();
    }

    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &drbg);

    if (mbedtls_ssl_setup(&ssl, &config) != 0) {
        FAIL();
    }

    if (mbedtls_ssl_set_hostname(&ssl, HOST) != 0) {
        FAIL();
    }

    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

    /* It is not necessary to initiate the handshake explicitly. It is automatically
     * performed on write, for instance. */
    /*
    if (mbedtls_ssl_handshake(&ssl) != 0) {
        FAIL();
    }
    */

    /* Write the GET request */
    printf("  > Write to server:");
    fflush(stdout);

    len = sprintf((char *)buf, GET_REQUEST);

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret != 0) {
            printf(" failed\n  ! write returned %d\n\n", ret);
            goto cleanup;
        }
    }

    len = ret;
    printf(" %d bytes written\n\n%s", len, (char *) buf);

    /*
     * Read the HTTP response
     */
    printf("  < Read from server:");
    fflush(stdout);
    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            break;
        } else if (ret <= 0) {
            printf("failed\n  ! ssl_read returned %d\n\n", ret);
            break;
        }

        len = ret;
        printf(" %d bytes read\n\n%s", len, (char *) buf);
    } while(1);

cleanup:
    mbedtls_ssl_config_free(&config);
    mbedtls_ssl_free(&ssl);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_net_free(&net);

    return(ret);
}

