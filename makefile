CC = gcc

CFLAGS = -Wall -g

all: lodi_client

lodi_client: lodi_client.o DieWithError.o
	$(CC) $(CFLAGS) -o lodi_client lodi_client.o DieWithError.o

lodi_client.o: lodi_client.c
	$(CC) $(CFLAGS) -c lodi_client.c

DieWithError.o: DieWithError.c
	$(CC) $(CFLAGS) -c DieWithError.c

clean:
	rm -f lodi_client *.o