/*lodi_server.c*/
#include "rsa.h"
#include "tfa_messages.h"
#include "pke_messages.h"
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
    struct sockaddr_in lodiServAddr;
    unsigned short lodiServerPort;
    
    //Lodi Client
    struct sockaddr_in lodiClientAddr; //address
    unsigned int lodiClientAddrLen; //length of incoming message?
    PClientToLodiServer loginRequest; //buffer for login message
    int loginRequestSize; //size of login message
    LodiServerToLodiClientAcks ackLoginMessage; //acknowlegement to be sent to client
    unsigned int ackLoginSize;

    //PKE Server
    struct sockaddr_in pkeServAddr; //pke server address
    unsigned short pkeServPort; //pke server port
    char *pkeServIP; //the ip address of the PKE server
    TOPKServer pkeRequest; //message to send to pke server
    FromPKServer pkeResponse; //buffer for response from PKE server

    //TFA Server
    struct sockaddr_in tfaServAddr; //tfa server address
    unsigned short tfaServPort; //tfa server port
    char *tfaServIP; //the ip address of the TFA server
    TFAClientOrLodiServerToTFAServer tfaRequest; //message to send to TFA server
    TFAServerToLodiServer tfaResponse; //buffer for response from TFA server

    //currently logged in
    struct sockaddr_in loggedInCLients[20]; //20 should be plenty for the number of clients we'll probably have
    char *userIds[20];
    int publicKeys[20];

    //check correct number of arguments
    if(argc != 2)
    {
        fprintf(stderr, "Usage: %s <Lodi Server Port>\n", argv[0]);
        exit(1);
    }

    lodiServerPort = atoi(argv[1]); //first argument is the local port

    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() fialed");

    //Construct local address structure
    memset(&lodiServAddr, 0, sizeof(lodiServAddr)); //zero out memory
    lodiServAddr.sin_family = AF_INET; //internet address family
    lodiServAddr.sin_addr.s_addr = htonl(INADDR_ANY); //any incoming interfaces
    lodiServAddr.sin_port = htons(lodiServerPort); //local port

    //bind socket to local address
    if(bind(sock, (struct sockaddr *) &lodiServAddr, sizeof(lodiServAddr)) < 0)
        DieWithError("bind() failed");

    
    for(;;) //run forever
    {
        printf("waiting for message %s\n");
        //set size of in/out parameter
        lodiClientAddrLen = sizeof(lodiClientAddr);

        //clear out memory for login request
        loginRequestSize = sizeof(loginRequest);
        memset(&loginRequest, 0, loginRequestSize);

        //block until message recieved (message struct must be cast to void *)
        if ((loginRequestSize = recvfrom(sock, (void *)&loginRequest, loginRequestSize, 0, 
                                            (struct sockaddr *) &lodiClientAddr, &lodiClientAddrLen)) < 0)
            DieWithError("recvfrom() failed");

        unsigned long clientPublicKey = computePublicKey(computePrivateKey(phiN), phiN);
        unsigned long decryptedValue = rsaDecrypt(loginRequest.digitalSig, clientPublicKey);

        printf("Received timestamp: %lu\n", loginRequest.timestamp);
        printf("Received signature: %lu\n", loginRequest.digitalSig);
        printf("Decrypted signature: %lu\n", decryptedValue);
        printf("Match: %s\n", (decryptedValue == loginRequest.timestamp) ? "YES" : "NO");

        //decrypt signature using key
        if(rsaDecrypt(loginRequest.digitalSig, clientPublicKey) != loginRequest.timestamp)
            DieWithError("Signature doesn't match timestamp");

        //send request to TFA server

        //recieve request from TFA server

        //printf("Message Recieved: %d%d\n", rsaDecrypt(loginRequest.digitalSig, pke), loginRequest.timestamp);

        //handle any errors with authentication

        //create message
        memset(&ackLoginMessage, 0, sizeof(ackLogin));
        ackLoginMessage.messageType = ackLogin;
        ackLoginMessage.userID = loginRequest.userID;
        ackLoginSize = sizeof(ackLoginMessage);

        //send a message back
        if (sendto(sock, (void *)&ackLoginMessage, ackLoginSize, 0,
                    (struct sockaddr *) &lodiClientAddr, lodiClientAddrLen) != ackLoginSize)
            DieWithError("Acknowlegement message failed to send");

    }
}