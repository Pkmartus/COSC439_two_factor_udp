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
    int sock;
    struct sockaddr_in fromAddr;
    unsigned short tfaServerPort;

    //TFA Client
    struct sockaddr_in tfaClientAddr;
    TFAClientOrLodiServerToTFAServer tfaRegister; //buffer for registering tfa message
    TFAServerToTFAClient tfaConfirm; //confirm tfa message
    TFAClientOrLodiServerToTFAServer tfaRegAck; //buffer for register acknowlegement
    TFAServerToTFAClient tfaPush; //message to send to TFA client
    TFAClientOrLodiServerToTFAServer pushAck; // buffer for push acknowlegement

    //Lodi Server
    struct sockaddr_in lodiServerAddr; //address
    TFAClientOrLodiServerToTFAServer authRequest; //buffer for auth request
    TFAServerToLodiServer authResponse; //message to send back to Lodi Server
    
    


   //process registration requests from TFA clients

    //process authentication requests from Lodi server

    //send PUSH notifiactions to the user's TFA client 
}

