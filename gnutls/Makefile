CC=gcc
CFLAGS=-std=gnu11 -Wall -Wextra -pedantic
LIBS=gnutls

connect: connect.c tcp.c
	$(CC) $(CFLAGS) -o $@ $^ $(addprefix -l,$(LIBS))

