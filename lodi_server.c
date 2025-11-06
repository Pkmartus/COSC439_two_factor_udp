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

#define TFA_DEFAULT_IP "127.0.0.1"
#define TFA_DEFAULT_PORT 5051
#define PKE_DEFAULT_IP "127.0.0.1"
#define PKE_DEFAULT_PORT 5052
#define LODI_DEFAULT_PORT 5050

int main(int argc, char *argv[])
{
    // local
    int sock; // socket
    struct sockaddr_in lodiServAddr;
    struct sockaddr_in fromAddr;
    unsigned int fromSize;
    unsigned short lodiServerPort;

    // Lodi Client
    struct sockaddr_in lodiClientAddr;          // address
    unsigned int lodiClientAddrLen;             // length of incoming message?
    PClientToLodiServer loginRequest;           // buffer for login message
    int loginRequestSize;                       // size of login message
    LodiServerToLodiClientAcks ackLoginMessage; // acknowlegement to be sent to client
    unsigned int ackLoginSize;

    // PKE Server
    struct sockaddr_in pkeServAddr; // pke server address
    unsigned short pkeServPort;     // pke server port
    char *pkeServIP;                // the ip address of the PKE server
    TOPKServer pkeRequest;          // message to send to pke server
    FromPKServer pkeResponse;       // buffer for response from PKE server
    unsigned int pkeResponseSize;

    // TFA Server
    struct sockaddr_in tfaServAddr;              // tfa server address
    unsigned short tfaServPort;                  // tfa server port
    char *tfaServIP;                             // the ip address of the TFA server
    TFAClientOrLodiServerToTFAServer tfaRequest; // message to send to TFA server
    TFAServerToLodiServer tfaResponse;           // buffer for response from TFA server
    unsigned int tfaResponseSize;

    // currently logged in
    struct sockaddr_in loggedInCLients[20]; // 20 should be plenty for the number of clients we'll probably have
    char *userIds[20];
    int publicKeys[20];

    // check correct number of arguments
    // if (argc != 2)
    // {
    //     fprintf(stderr, "Usage: %s <Lodi Server Port>\n", argv[0]);
    //     exit(1);
    // }

    lodiServerPort = LODI_DEFAULT_PORT; // first argument is the local port

    // Create datagram UDP Socket
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() fialed");

    // Construct local address structure
    memset(&lodiServAddr, 0, sizeof(lodiServAddr));   // zero out memory
    lodiServAddr.sin_family = AF_INET;                // internet address family
    lodiServAddr.sin_addr.s_addr = htonl(INADDR_ANY); // any incoming interfaces
    lodiServAddr.sin_port = htons(lodiServerPort);    // local port

    // bind socket to local address
    if (bind(sock, (struct sockaddr *)&lodiServAddr, sizeof(lodiServAddr)) < 0)
        DieWithError("bind() failed");

    // //get ip from keyboard
    // printf("Enter IP for Primary Key Server: \n");
    // scanf("%15s", pkeServIP);

    // //get the server port
    // printf("Enter port for Primary Key Server: \n");
    // scanf("%hu", &pkeServPort);

    // //get ip from keyboard
    // printf("Enter IP for Two Factor Server: \n");
    // scanf("%15s", tfaServIP);

    // //get the server port
    // printf("Enter port for Two Factor Server: \n");
    // scanf("%hu", &tfaServPort);

    //setup pke ip and port
    pkeServIP = PKE_DEFAULT_IP;
    pkeServPort = PKE_DEFAULT_PORT;

    //setup tfa ip and port
    tfaServIP = TFA_DEFAULT_IP;
    tfaServPort = TFA_DEFAULT_PORT;

    for (;;) // run forever
    {
        // recieve login request from client

        printf("waiting for message from clients \n");

        // set size of in/out parameter
        lodiClientAddrLen = sizeof(lodiClientAddr);

        // clear out memory for login request
        loginRequestSize = sizeof(loginRequest);
        memset(&loginRequest, 0, loginRequestSize);

        // block until message recieved (message struct must be cast to void *)
        if ((loginRequestSize = recvfrom(sock, (void *)&loginRequest, loginRequestSize, 0,
                                         (struct sockaddr *)&lodiClientAddr, &lodiClientAddrLen)) < 0)
            DieWithError("recvfrom() failed");

        // request public key from PKE Server

        // submit users public key to PKE server

        // set message values
        memset(&pkeRequest, 0, sizeof(pkeRequest));
        pkeRequest.messageType = requestKey;
        pkeRequest.userID = loginRequest.userID;

        // set PKE server address structure
        memset(&pkeServAddr, 0, sizeof(pkeServAddr));
        pkeServAddr.sin_family = AF_INET;
        pkeServAddr.sin_addr.s_addr = inet_addr(pkeServIP);
        pkeServAddr.sin_port = htons(pkeServPort);

        // send primary key to pke server
        if (sendto(sock, (void *)&pkeRequest, sizeof(pkeRequest), 0,
                   (struct sockaddr *)&pkeServAddr, sizeof(pkeServAddr)) != sizeof(pkeRequest))
            DieWithError("sendto() pke server sent a different number of bytes than expected");

        // recieve acknowlegement from pke server
        fromSize = sizeof(fromAddr);
        pkeResponseSize = sizeof(pkeResponse);
        memset(&pkeResponse, 0, pkeResponseSize); // zero out structure

        if ((pkeResponseSize = recvfrom(sock, (void *)&pkeResponse, pkeResponseSize, 0,
                                   (struct sockaddr *)&fromAddr, &fromSize)) < 0)
            DieWithError("Recieving Public Key from server failed");

        // check that response came from correct server
        if (pkeServAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr)
            DieWithError("Packet from unknown source");

        printf("response recieved from pke server \n");

        // decrypt signature using key
        if (rsaDecrypt(loginRequest.digitalSig, pkeResponse.publicKey) != loginRequest.timestamp)
            DieWithError("Signature doesn't match timestamp");

        printf("Digital signature verified with public key \n");

        
        // send request to TFA server

        // set message values
        memset(&tfaRequest, 0, sizeof(tfaRequest));
        tfaRequest.messageType = requestAuth;
        tfaRequest.userID = loginRequest.userID;
        tfaRequest.timeStamp = loginRequest.timestamp;
        tfaRequest.digitalSig = loginRequest.digitalSig;

        // set TFA server address structure
        memset(&tfaServAddr, 0, sizeof(tfaServAddr));
        tfaServAddr.sin_family = AF_INET;
        tfaServAddr.sin_addr.s_addr = inet_addr(tfaServIP);
        tfaServAddr.sin_port = htons(tfaServPort);

        //send auth request to tfa server
        if (sendto(sock, (void *)&tfaRequest, sizeof(tfaRequest), 0,
                   (struct sockaddr *)&tfaRequest, sizeof(tfaRequest)) != sizeof(tfaRequest))
            DieWithError("sendto tfa server sent a different number of bytes than expected");

        //wait for response from TFA server
        fromSize = sizeof(fromAddr);
        tfaResponseSize = sizeof(tfaResponse);
        memset(&tfaResponse, 0, tfaResponseSize); // zero out structure

        if ((tfaResponseSize = recvfrom(sock, (void *)&tfaResponse, tfaResponseSize, 0,
                                   (struct sockaddr *)&fromAddr, &fromSize)) < 0)
            DieWithError("Two Factor Auth failed");
        
        //send login acknowlegment to client
        // create message
        memset(&ackLoginMessage, 0, sizeof(ackLogin));
        ackLoginMessage.messageType = ackLogin;
        ackLoginMessage.userID = loginRequest.userID;
        ackLoginSize = sizeof(ackLoginMessage);

        // send a message back
        if (sendto(sock, (void *)&ackLoginMessage, ackLoginSize, 0,
                   (struct sockaddr *)&lodiClientAddr, lodiClientAddrLen) != ackLoginSize)
            DieWithError("Acknowlegement message failed to send");
    }
}