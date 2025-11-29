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
PClientToLodiServer recvFromClient(int tcpSock);
unsigned int findUser(int userID, UserSignInStatus listUsers[], int numUsers);

#define MAX_ENTRIES 20
#define MAXPENDING 20 // maximum pending client connections

int main(int argc, char *argv[])
{
    // local
    int udpSock; // socket for communicating with tfa and pke server
    struct sockaddr_in lodiServAddr;
    struct sockaddr_in fromAddr;
    unsigned int fromSize;
    unsigned short lodiServerPort;

    // TODO change to tcp
    //  Lodi Client
    int lodiClientSock;                // new to project 2, socket for the lodi client
    struct sockaddr_in lodiClientAddr; // address
    unsigned int lodiClientAddrLen;    // length of address
    PClientToLodiServer lodiClientMsg; // buffer for client message
    int lodiClientMsgSize;             // size of client message
    LodiServerMessage lodiResponseMsg; // acknowlegement to be sent to client
    unsigned int lodiResponseMsgSize;

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

    // Data structures for login
    UserSignInStatus loggedInUsers[MAX_ENTRIES];
    unsigned int numUsers = 0; //count of the users kept in loggedIn Users
    UserMessages messages[100];  // keep track of messages each user has sent
    unsigned int numMessages = 0; //number of messages in list
    // FollowingIdol following[MAX_ENTRIES*MAX_ENTRIES]; // keep track of who's following who

    lodiServerPort = LODI_DEFAULT_PORT; // first argument is the local port

    // Create datagram UDP Socket
    if ((udpSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("[Lodi_Server] socket() fialed");
    printf("[Lodi_Server] UDP Socket Created \n");

    // Construct local address structure
    memset(&lodiServAddr, 0, sizeof(lodiServAddr));   // zero out memory
    lodiServAddr.sin_family = AF_INET;                // internet address family
    lodiServAddr.sin_addr.s_addr = htonl(INADDR_ANY); // any incoming interfaces
    lodiServAddr.sin_port = htons(lodiServerPort);    // local port

    // setup pke ip and port
    pkeServIP = PKE_DEFAULT_IP;
    pkeServPort = PKE_DEFAULT_PORT;

    // set PKE server address structure
    memset(&pkeServAddr, 0, sizeof(pkeServAddr));
    pkeServAddr.sin_family = AF_INET;
    pkeServAddr.sin_addr.s_addr = inet_addr(pkeServIP);
    pkeServAddr.sin_port = htons(pkeServPort);

    // setup tfa ip and port
    tfaServIP = TFA_DEFAULT_IP;
    tfaServPort = TFA_DEFAULT_PORT;

    // set TFA server address structure
    memset(&tfaServAddr, 0, sizeof(tfaServAddr));
    tfaServAddr.sin_family = AF_INET;
    tfaServAddr.sin_addr.s_addr = inet_addr(tfaServIP);
    tfaServAddr.sin_port = htons(tfaServPort);

    // create tcp socket for communicating with the client
    if ((lodiClientSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        DieWithError("socket() failed");
    printf("[Lodi_Server] TCP socket created\n");

    // bind the tcp socket
    if (bind(lodiClientSock, (struct sockaddr *)&lodiServAddr, sizeof(lodiServAddr)) < 0)
        DieWithError("bind() failed");
    printf("[Lodi_Server] TCP socket bound\n");

    // make the tcp socket listen for messages from server
    if (listen(lodiClientSock, MAXPENDING) < 0)
        DieWithError("listen() failed");
    printf("[Lodi_Server] TCP socket listening\n");


    for (;;) // run forever
    {
        printf("[Lodi_Server] Listening on port: %d \n", lodiServerPort);
        // set size of in/out parameter
        lodiClientAddrLen = sizeof(lodiClientAddr);

        // clear out memory for login request
        lodiClientMsgSize = sizeof(lodiClientMsg);
        memset(&lodiClientMsg, 0, lodiClientMsgSize);

        // try and accept connection from clients
        if ((lodiClientSock = accept(lodiClientSock, (struct sockaddr *)&lodiClientAddr,
                                     &lodiClientAddrLen)) < 0)
            DieWithError("accept() failed");
        printf("[Lodi_Server] Listening on port: %d \n", lodiServerPort);

        // if ((lodiClientMsgSize = recv(lodiClientSock, &lodiClientMsg, sizeof(lodiClientMsg), 0)) < 0)
        //     DieWithError("recv() failed");

        //function to accumulate method
        lodiClientMsg = recvFromClient(lodiClientSock);
            
        printf("[Lodi_Server] Recieved Message from a client\n");

        // TODO determine the type of message being sent and respond accordingly
        switch (lodiClientMsg.messageType)
        {
            case login:
                // set message values
                memset(&pkeRequest, 0, sizeof(pkeRequest));
                pkeRequest.messageType = requestKey;
                pkeRequest.userID = lodiClientMsg.userID;

                // send primary key to pke server
                if (sendto(udpSock, (void *)&pkeRequest, sizeof(pkeRequest), 0,
                           (struct sockaddr *)&pkeServAddr, sizeof(pkeServAddr)) != sizeof(pkeRequest))
                    DieWithError("[Lodi_Server] sendto() pke server sent a different number of bytes than expected");
                printf("[Lodi_Server] Request -> request public key for user: %d\n", lodiClientMsg.userID);

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
                if (rsaDecrypt(lodiClientMsg.digitalSig, pkeResponse.publicKey) != lodiClientMsg.timestamp)
                    DieWithError("[Lodi_Server] Signature doesn't match timestamp");

                printf("[Lodi_Server] Digital signature verified with public key\n");

                // send request to TFA server

                // set message values
                memset(&tfaRequest, 0, sizeof(tfaRequest));
                tfaRequest.messageType = requestAuth;
                tfaRequest.userID = lodiClientMsg.userID;
                tfaRequest.timeStamp = lodiClientMsg.timestamp;
                tfaRequest.digitalSig = lodiClientMsg.digitalSig;

                // send auth request to tfa server
                if (sendto(udpSock, (void *)&tfaRequest, sizeof(tfaRequest), 0,
                           (struct sockaddr *)&tfaServAddr, sizeof(tfaServAddr)) != sizeof(tfaRequest))
                    DieWithError("[Lodi_Server] sendto tfa server sent a different number of bytes than expected");
                printf("[Lodi_Server] Request -> auth from TFA Server for %d\n", lodiClientMsg.userID);

                // wait for response from TFA server
                fromSize = sizeof(fromAddr);
                tfaResponseSize = sizeof(tfaResponse);
                memset(&tfaResponse, 0, tfaResponseSize); // zero out structure

                if ((tfaResponseSize = recvfrom(udpSock, (void *)&tfaResponse, tfaResponseSize, 0,
                                                (struct sockaddr *)&fromAddr, &fromSize)) < 0)
                    DieWithError("[Lodi_Server] Two Factor Auth failed");
                printf("[Lodi_Server] Response <- auth recieved from TFA Server for: %d\n", tfaResponse.userID);

                //add user logged in clients
                unsigned int userIndex;
                if (numUsers < MAX_ENTRIES)
                {
                    //if user has logged in before log them back in
                    if((userIndex = findUser(lodiClientMsg.userID, loggedInUsers, numUsers)) >= 0){
                        loggedInUsers[userIndex].signedIn = 1;
                        printf("[Lodi_Server] user: %d signed back in\n", loggedInUsers[userIndex].userID);
                    } else { //if not create a new user and add it to the list
                        UserSignInStatus newuser;
                        memset(&newuser, 0, sizeof(UserSignInStatus));
                        newuser.userID = lodiClientMsg.userID;
                        newuser.signedIn = 1;
                        loggedInUsers[numUsers] = newuser;
                        ++numUsers;
                        printf("[Lodi_Server] REGISTER user=%u\n", lodiClientMsg.userID);
                    }
                } else {
                    DieWithError("[Lodi_Server] List of users is full");
                }

                // send login acknowlegment to client
                //  create message
                memset(&lodiResponseMsg, 0, sizeof(ackLogin));
                lodiResponseMsg.messageType = ackLogin;
                lodiResponseMsg.userID = lodiClientMsg.userID;
                lodiResponseMsgSize = sizeof(lodiResponseMsg);

                // send a message back
                if (send(lodiClientSock, (void *)&lodiResponseMsg, lodiResponseMsgSize, 0) != lodiResponseMsgSize)
                    DieWithError("[Lodi_Server] Acknowlegement message failed to send");
                printf("[Lodi_Server] Response -> Ack Login to Lodi Client for user: %d\n", lodiClientMsg.userID);
                break;
            case post:
                // TODO ack post
                // store the post and the idol who posted it
                break;
            case feed:
                // TODO feed
                // send messages with how many posts are incoming
                // send all posts from followed idols
                break;
            case follow:
                // TODO follow
                // server should update list of idols the fan is following
                break;
            case unfollow:
                // TODO unfollow
                // server updates the list of idols to remove idol
                break;
            case logout:
                // TODO logout
                // server updates logged in users. list of followed idols should stay
                break;
            default:
                printf("[Lodi_Server] Recieved <- Invalid message type\n");
                break;            
        }
    
    }
}

//should be very similar to the recieve portion of sendMessage on the client side
PClientToLodiServer recvFromClient(int tcpSock) {
    PClientToLodiServer messageBuffer; //buffer for incomint message
    int totalBytesRcvd, bytesRcvd;

    totalBytesRcvd = 0;
    while (totalBytesRcvd < sizeof(messageBuffer))
    {
        //accumulate up to the buffer size
        if ((bytesRcvd = recv(tcpSock, ((char *)&messageBuffer) + totalBytesRcvd, sizeof(messageBuffer) - totalBytesRcvd, 0)) <= 0)
            DieWithError("recv() failed or connection closed prematurely");
        totalBytesRcvd += bytesRcvd;   /* Keep tally of total bytes */
    }
    //may or may not need to close at the end of this function

    return messageBuffer;
}

unsigned int findUser(int userID, UserSignInStatus listUsers[], int numUsers) {
    for(int i = 0; i < numUsers; i++) {
        if(userID == listUsers[i].userID)
        {
            return i;
        }
    }
    return -1;
}