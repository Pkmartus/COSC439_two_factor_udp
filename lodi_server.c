/*lodi_server.c*/
// Primary Dev Patrick Martus
//(most logic based on examples)
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

#define MAX_ENTRIES 20
#define MAXPENDING 20 //maximum pending client connections

int main(int argc, char *argv[])
{
    // local
    int udpSock; // socket
    struct sockaddr_in lodiServAddr;
    struct sockaddr_in fromAddr;
    unsigned int fromSize;
    unsigned short lodiServerPort;

    //TODO change to tcp
    // Lodi Client
    int clientTCPSock;                             //new to project 2, socket for the lodi client
    struct sockaddr_in lodiClientAddr;          // address
    unsigned int lodiClientAddrLen;             // length of incoming message?
    PClientToLodiServer loginRequest;           // buffer for login message
    int loginRequestSize;                       // size of login message
    LodiServerMessage ackLoginMessage; // acknowlegement to be sent to client
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

    lodiServerPort = LODI_DEFAULT_PORT; // first argument is the local port

    // Create datagram UDP Socket
    if ((udpSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("[Lodi_Server] socket() fialed");

    // Construct local address structure
    memset(&lodiServAddr, 0, sizeof(lodiServAddr));   // zero out memory
    lodiServAddr.sin_family = AF_INET;                // internet address family
    lodiServAddr.sin_addr.s_addr = htonl(INADDR_ANY); // any incoming interfaces
    lodiServAddr.sin_port = htons(lodiServerPort);    // local port

    // bind socket to local address
    if (bind(udpSock, (struct sockaddr *)&lodiServAddr, sizeof(lodiServAddr)) < 0)
        DieWithError("bind() failed");

    // setup pke ip and port
    pkeServIP = PKE_DEFAULT_IP;
    pkeServPort = PKE_DEFAULT_PORT;

    // setup tfa ip and port
    tfaServIP = TFA_DEFAULT_IP;
    tfaServPort = TFA_DEFAULT_PORT;

    //create tcp socket for communicating with the client
    if ((clientTCPSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        DieWithError("socket() failed");

    //bind the tcp socket
    if (bind(clientTCPSock, (struct sockaddr *) &lodiServAddr, sizeof(lodiServAddr)) < 0)
        DieWithError("bind() failed");

    //make the tcp socket listen for messages from server
    if (listen(clientTCPSock, MAXPENDING) < 0)
        DieWithError("listen() failed");

    //Data structures for login
    unsigned int loggedInUsers[20];

    //keep track of messages each user has sent
    UserMessages messages[100];

    //keep track of who's following who
    FollowingIdol following[40];

    for (;;) // run forever
    {

        //TODO determine the type of message being sent and respond accordingly

        // recieve login request from client

        printf("[Lodi_Server] Listening on port: %d \n", lodiServerPort);

        // set size of in/out parameter
        lodiClientAddrLen = sizeof(lodiClientAddr);

        // clear out memory for login request
        loginRequestSize = sizeof(loginRequest);
        memset(&loginRequest, 0, loginRequestSize);

        // block until message recieved (message struct must be cast to void *)
        if ((loginRequestSize = recvfrom(udpSock, (void *)&loginRequest, loginRequestSize, 0,
                                         (struct sockaddr *)&lodiClientAddr, &lodiClientAddrLen)) < 0)
            DieWithError("[Lodi_Server] recvfrom() failed");
        printf("[Lodi_Server] Recieved <- login request from user: %d\n", loginRequest.userID);

        // request public key from PKE Server

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
        if (sendto(udpSock, (void *)&pkeRequest, sizeof(pkeRequest), 0,
                   (struct sockaddr *)&pkeServAddr, sizeof(pkeServAddr)) != sizeof(pkeRequest))
            DieWithError("[Lodi_Server] sendto() pke server sent a different number of bytes than expected");
        printf("[Lodi_Server] Request -> request public key for user: %d\n", loginRequest.userID);

        // recieve acknowlegement from pke server
        fromSize = sizeof(fromAddr);
        pkeResponseSize = sizeof(pkeResponse);
        memset(&pkeResponse, 0, pkeResponseSize); // zero out structure

        if ((pkeResponseSize = recvfrom(udpSock, (void *)&pkeResponse, pkeResponseSize, 0,
                                        (struct sockaddr *)&fromAddr, &fromSize)) < 0)
            DieWithError("[Lodi_Server] Recieving Public Key from server failed");

        // check that response came from correct server
        if (pkeServAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr)
            DieWithError("[Lodi_Server] Packet from unknown source");

        printf("[Lodi_Server] Response <- recieved from pke server key: %d\n", pkeResponse.publicKey);

        // decrypt signature using key
        if (rsaDecrypt(loginRequest.digitalSig, pkeResponse.publicKey) != loginRequest.timestamp)
            DieWithError("[Lodi_Server] Signature doesn't match timestamp");

        printf("[Lodi_Server] Digital signature verified with public key\n");

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

        // send auth request to tfa server
        if (sendto(udpSock, (void *)&tfaRequest, sizeof(tfaRequest), 0,
                   (struct sockaddr *)&tfaServAddr, sizeof(tfaServAddr)) != sizeof(tfaRequest))
            DieWithError("[Lodi_Server] sendto tfa server sent a different number of bytes than expected");
        printf("[Lodi_Server] Request -> auth from TFA Server for %d\n", loginRequest.userID);

        // wait for response from TFA server
        fromSize = sizeof(fromAddr);
        tfaResponseSize = sizeof(tfaResponse);
        memset(&tfaResponse, 0, tfaResponseSize); // zero out structure

        if ((tfaResponseSize = recvfrom(udpSock, (void *)&tfaResponse, tfaResponseSize, 0,
                                        (struct sockaddr *)&fromAddr, &fromSize)) < 0)
            DieWithError("[Lodi_Server] Two Factor Auth failed");
        printf("[Lodi_Server] Response <- auth recieved from TFA Server for: %d\n", tfaResponse.userID);

        // add user logged in clients
        // if (numUsers < MAX_ENTRIES)
        // {
        //     loggedInCLientIDs[numUsers] = loginRequest.userID;
        //     ++numUsers;
        //     printf("[Lodi_SERVER] REGISTER user=%u\n", loginRequest.userID);
        // }

        // send login acknowlegment to client
        //  create message
        memset(&ackLoginMessage, 0, sizeof(ackLogin));
        ackLoginMessage.messageType = ackLogin;
        ackLoginMessage.userID = loginRequest.userID;
        ackLoginSize = sizeof(ackLoginMessage);

        // send a message back
        if (sendto(udpSock, (void *)&ackLoginMessage, ackLoginSize, 0,
                   (struct sockaddr *)&lodiClientAddr, lodiClientAddrLen) != ackLoginSize)
            DieWithError("[Lodi_Server] Acknowlegement message failed to send");
        printf("[Lodi_Server] Response -> to Lodi Client for user: %d\n", loginRequest.userID);

        //TODO ack post
        //store the post and the idol who posted it

        //TODO ack feed
        //send messages with how many posts are incoming
        //send all posts from followed idols

        //TODO ack follow
        //server should update list of idols the fan is following

        //TODO ack unfollow
        //server updates the list of idols to remove idol

        //TODO ack logout
        //server updates logged in users. list of followed idols should stay
    }
}