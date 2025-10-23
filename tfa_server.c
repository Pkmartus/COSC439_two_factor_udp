#include "pke_messages.h"
#include "tfa_messages.h"
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
    struct sockaddr_in fromAddr;
    unsigned short tfaServerPort;

    //TFA Client
    //todo create a list of tfa clients allowing for a push to be sent back to those clients
    struct sockaddr_in tfaClientAddr;
    TFAClientOrLodiServerToTFAServer tfaRegister; //buffer for registering tfa message
    TFAServerToTFAClient tfaConfirm; //confirm tfa message
    TFAClientOrLodiServerToTFAServer tfaRegAck; //buffer for register acknowlegement
    TFAServerToTFAClient tfaPush; //message to send to TFA client
    TFAClientOrLodiServerToTFAServer pushAck; // buffer for push acknowlegement

    //PKE Server
    int pkeSock;
    unsigned short pkeServPort; //lodi server port
    char *pkeServIP; //ip of lodi server
    struct sockaddr_in pkeserverAddr;
    TOPKServer pkRequest;
    FromPKServer pkResponse;

    //list of registered clients
    char *userIds[20]; //array of 20 strings of a length up to 30
    int publicKeys[20];

    //Lodi Server
    struct sockaddr_in lodiServerAddr; //address
    TFAClientOrLodiServerToTFAServer authRequest; //buffer for auth request
    TFAServerToLodiServer authResponse; //message to send back to Lodi Server
    
    


   //process registration requests from TFA clients

    //process authentication requests from Lodi server

    //send PUSH notifiactions to the user's TFA client 
}

