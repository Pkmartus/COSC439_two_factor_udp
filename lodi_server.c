#include "tfa_messages.h"
#include "lodi_messages.h"
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void DieWithError(char *errorMessage);

int main(int argc, char *argv[]) 
{
    //local
    int sock; //socket
    struct sockaddr_in fromAddr;
    unsigned short lodiServerPort;
    
    //Lodi Client
    struct sockaddr_in lodiClientAddr; //address
    PClientToLodiServer loginRequest; //buffer for login message

    //PKE Server
    struct sockaddr_in pkeServAddr; //pke server address
    unsigned short pkeServPort; //pke server port
    char *pkeServIP; //the ip address of the PKE server
    PClientTOPKServer pkeRequest; //message to send to pke server
    PKServerTOPClientOrLodiServer pkeResponse; //buffer for response from PKE server

    //TFA Server
    struct sockaddr_in tfaServAddr; //tfa server address
    unsigned short tfaServPort; //tfa server port
    char *tfaServIP; //the ip address of the TFA server
    TFAClientOrLodiServerToTFAServer tfaRequest; //message to send to TFA server
    TFAServerToLodiServer tfaResponse; //buffer for response from TFA server




    //Recieve a login message from Lodi client
}