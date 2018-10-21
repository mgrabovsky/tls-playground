CC=gcc
CFLAGS=-std=gnu11 -Wall -Wextra -pedantic
LIBS=$(addprefix mbed,crypto tls x509)

connect: connect.c
	$(CC) $(CFLAGS) -o $@ $^ $(addprefix -l,$(LIBS))

