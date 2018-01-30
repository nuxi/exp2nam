CFLAGS=-O2 -g -Wall
LDFLAGS=
CC=gcc

all: exp2nam

exp2nam: exp2nam.o
	$(CC) $(LDFLAGS) -lcrypto -o $@ $^
exp2nam.o: exp2nam.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	$(RM) exp2nam *.o
.PHONY: clean all
