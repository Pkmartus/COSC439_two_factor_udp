#include <pke_messages.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void DieWithError(char *errorMessage);

int main(int argc, char * argv[])
{
    //local
    int sock; //socket
    struct sockaddr_in fromAddr;
    unsigned short pkeServerPort;

    //todo create a list of lodi clients and primary keys so that the keys can be retrieved by request key events
    //Incoming message could be from Lodi client, Lodi Server, or PKE Server
    struct sockaddr_in lodiClientAddr; //address
    TOPKServer clientRegisterKey; //buffer for register key message

    //registered list of pke clients
    char *registeredUserIds[20];
    int registeredPublicKeys[20];

    
    //process key registration

    //procccss key requests
}