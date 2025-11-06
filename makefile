CC = gcc

CFLAGS = -Wall -g

all: lodi_client lodi_server pke_server tfa_client tfa_server

lodi_client: lodi_client.o DieWithError.o 
	$(CC) $(CFLAGS) -o lodi_client lodi_client.o DieWithError.o

lodi_server: lodi_server.o DieWithError.o
	$(CC) $(CFLAGS) -o lodi_server lodi_server.o DieWithError.o

lodi_server.o: lodi_server.c
	$(CC) $(CFLAGS) -c lodi_server.c

lodi_client.o: lodi_client.c
	$(CC) $(CFLAGS) -c lodi_client.c

pke_server: pke_server.o DieWithError.o
	$(CC) $(CFLAGS) -o pke_server pke_server.o DieWithError.o

pke_server.o: pke_server.c
	$(CC) $(CFLAGS) -c pke_server.c

tfa_client: tfa_client.o DieWithError.o
	$(CC) $(CFLAGS) -o tfa_client tfa_client.o DieWithError.o

tfa_client.o: tfa_client.c
	$(CC) $(CFLAGS) -c tfa_client.c

tfa_server: tfa_server.o DieWithError.o
	$(CC) $(CFLAGS) -o tfa_server tfa_server.o DieWithError.o

tfa_server.o: tfa_server.c
	$(CC) $(CFLAGS) -c tfa_server.c

DieWithError.o: DieWithError.c
	$(CC) $(CFLAGS) -c DieWithError.c

clean:
	rm -f lodi_client lodi_server pke_server tfa_client tfa_server *.o