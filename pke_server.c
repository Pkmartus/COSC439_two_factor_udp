#include "lodi_messages.h"
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

    //Lodi Client
    struct sockaddr_in lodiClientAddr; //address
    PClientToLodiServer clientRegisterKey; //buffer for register key message

    //Lodi Server
    struct sockaddr_in lodiServerAddr; //address
    PClientToLodiServer serverRequestKey; //buffer for request PK message

    
    //process key registration

    //procccss key requests
}