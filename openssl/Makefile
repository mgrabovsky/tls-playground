CC=gcc
CFLAGS=-std=gnu11 -Wall -Wextra -pedantic
LIBS=crypto ssl

connect: connect.c
	$(CC) $(CFLAGS) -o $@ $^ $(addprefix -l,$(LIBS))

