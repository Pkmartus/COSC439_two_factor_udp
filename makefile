CC = gcc

CFLAGS = -Wall -g

all: lodi_client lodi_server

lodi_client: lodi_client.o DieWithError.o 
	$(CC) $(CFLAGS) -o lodi_client lodi_client.o DieWithError.o

lodi_server: lodi_server.o DieWithError.o
	$(CC) $(CFLAGS) -o lodi_server lodi_server.o DieWithError.o

lodi_server.o: lodi_server.c
	$(CC) $(CFLAGS) -c lodi_server.c

lodi_client.o: lodi_client.c
	$(CC) $(CFLAGS) -c lodi_client.c

DieWithError.o: DieWithError.c
	$(CC) $(CFLAGS) -c DieWithError.c

clean:
	rm -f lodi_client lodi_server *.o