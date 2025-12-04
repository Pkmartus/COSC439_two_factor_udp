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
int findUser(int userID);
void printLoggedInUsers(UserSignInStatus usersList[], int numUsers);
int findIdol(int idolID, unsigned int listIdols[], int numIdols);
void getFeed(int userID);

#define MAX_ENTRIES 20
#define MAXPENDING 20 // maximum pending client connections

// local
int udpSock; // socket for communicating with tfa and pke server
struct sockaddr_in lodiServAddr;
struct sockaddr_in fromAddr;
unsigned int fromSize;
unsigned short lodiServerPort;

//  Lodi Client
int listenForClientSock;
int connectToClientSock;           // new to project 2, socket for the lodi client
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
unsigned int numUsers = 0;    // count of the users kept in loggedIn Users
UserMessages messages[100];   // keep track of messages each user has sent
unsigned int numMessages = 0; // number of messages in list
// FollowingIdol following[MAX_ENTRIES*MAX_ENTRIES]; // keep track of who's following who

int userIndex;
int idolIndex;
int numInFeed;
UserMessages userFeed[100];

int main(int argc, char *argv[])
{
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
    if ((listenForClientSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        DieWithError("socket() failed");
    printf("[Lodi_Server] TCP socket created\n");

    // bind the tcp socket
    if (bind(listenForClientSock, (struct sockaddr *)&lodiServAddr, sizeof(lodiServAddr)) < 0)
        DieWithError("bind() failed");
    printf("[Lodi_Server] TCP socket bound\n");

    // make the tcp socket listen for messages from server
    if (listen(listenForClientSock, MAXPENDING) < 0)
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
        if ((connectToClientSock = accept(listenForClientSock, (struct sockaddr *)&lodiClientAddr,
                                          &lodiClientAddrLen)) < 0)
            DieWithError("accept() failed");
        printf("[Lodi_Server] Listening on port: %d \n", lodiServerPort);

        // if ((lodiClientMsgSize = recv(lodiClientSock, &lodiClientMsg, sizeof(lodiClientMsg), 0)) < 0)
        //     DieWithError("recv() failed");

        // function to accumulate method
        lodiClientMsg = recvFromClient(connectToClientSock);

        printf("[Lodi_Server] Recieved <- Message from a client\n");

        // determine the type of message being sent and respond accordingly
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

            // add user logged in clients
            if (numUsers < MAX_ENTRIES)
            {
                // if user has logged in before log them back in
                if ((userIndex = findUser(lodiClientMsg.userID)) >= 0)
                {
                    loggedInUsers[userIndex].signedIn = 1;
                    printf("[Lodi_Server] user: %d signed back in\n", loggedInUsers[userIndex].userID);
                }
                else
                { // if not create a new user and add it to the list
                    UserSignInStatus newuser;
                    memset(&newuser, 0, sizeof(UserSignInStatus));
                    newuser.userID = lodiClientMsg.userID;
                    newuser.signedIn = 1;
                    newuser.numIdols = 0;
                    loggedInUsers[numUsers] = newuser;
                    ++numUsers;
                    // verify that the user is now logged in
                    printf("[Lodi_Server] REGISTER user=%u\n", loggedInUsers[findUser(lodiClientMsg.userID)].userID);
                }
            }
            else
            {
                DieWithError("[Lodi_Server] List of users is full");
            }

            // send login acknowlegment to client
            //  create message
            memset(&lodiResponseMsg, 0, sizeof(lodiResponseMsg));
            lodiResponseMsg.messageType = ackLogin;
            lodiResponseMsg.userID = lodiClientMsg.userID;
            sprintf(lodiResponseMsg.message, "%s\n", "Login successful\n");
            lodiResponseMsgSize = sizeof(lodiResponseMsg);

            // send a message back
            if (send(connectToClientSock, (void *)&lodiResponseMsg, lodiResponseMsgSize, 0) != lodiResponseMsgSize)
                DieWithError("[Lodi_Server] Acknowlegement message failed to send");
            printf("[Lodi_Server] Response -> Ack Login to Lodi Client for user: %d\n", lodiClientMsg.userID);
            break;
        case post:
            // add the message and userID to the array
            messages[numMessages].userID = lodiClientMsg.userID;
            strncpy(messages[numMessages].message, lodiClientMsg.message, sizeof(messages[numMessages].message) - 1);
            messages[numMessages].message[sizeof(messages[numMessages].message) - 1] = '\0';

            // TODO ack post
            // create message
            memset(&lodiResponseMsg, 0, sizeof(lodiResponseMsg));
            lodiResponseMsg.messageType = ackPost;
            lodiResponseMsg.userID = messages[numMessages].userID;
            sprintf(lodiResponseMsg.message, "post successful: %s\n", messages[numMessages].message);
            lodiResponseMsgSize = sizeof(lodiResponseMsg);
            numMessages++;

            // send ack
            if (send(connectToClientSock, (void *)&lodiResponseMsg, lodiResponseMsgSize, 0) != lodiResponseMsgSize)
                DieWithError("[Lodi_Server] Acknowlegement message failed to send");
            printf("[Lodi_Server] Response -> Ack Message: %s to Lodi Client for user: %d\n", lodiResponseMsg.message, lodiClientMsg.userID);
            break;
        case feed:
            // TODO feed
            // collect messages in feed
            getFeed(lodiClientMsg.userID);

            // send message with how many posts are incoming

            // send all posts from followed idols
            break;
        case follow:
            // follow
            memset(&lodiResponseMsg, 0, sizeof(lodiResponseMsg));
            lodiResponseMsg.messageType = ackFollow;
            lodiResponseMsg.userID = lodiClientMsg.userID;
            // find index of user first
            if ((userIndex = findUser(lodiClientMsg.userID)) >= 0)
            {
                // server should update list of idols the fan is following
                if ((idolIndex = findUser(lodiClientMsg.recipientID)) >= 0)
                {
                    // add user to list of followed users
                    loggedInUsers[userIndex].folllowedIdolIDs[loggedInUsers[userIndex].numIdols] = lodiClientMsg.recipientID;
                    loggedInUsers[userIndex].numIdols += 1;
                    sprintf(lodiResponseMsg.message, "Successfully Followed User: %d", lodiClientMsg.recipientID);
                }
                else
                {
                    sprintf(lodiResponseMsg.message, "Couldn't follow User: %d, not found", lodiClientMsg.recipientID);
                }
            }
            else
            {
                sprintf(lodiResponseMsg.message, "User: %d not logged in", lodiClientMsg.userID);
            }

            lodiResponseMsgSize = sizeof(lodiResponseMsg);

            // send ack
            if (send(connectToClientSock, (void *)&lodiResponseMsg, lodiResponseMsgSize, 0) != lodiResponseMsgSize)
                DieWithError("[Lodi_Server] Acknowlegement message failed to send");
            // todo change result to reflect the actual result
            printf("[Lodi_Server] Response -> Ack Message: User: %d %s\n", lodiClientMsg.userID, lodiResponseMsg.message);
            break;
        case unfollow:
            // TODO unfollow
            memset(&lodiResponseMsg, 0, sizeof(lodiResponseMsg));
            lodiResponseMsg.messageType = ackFollow;
            lodiResponseMsg.userID = lodiClientMsg.userID;
            // find index of user first
            if ((userIndex = findUser(lodiClientMsg.userID)) >= 0)
            {
                // find idol in list of followed users
                if ((idolIndex = findIdol(lodiClientMsg.recipientID, loggedInUsers[userIndex].folllowedIdolIDs, loggedInUsers[userIndex].numIdols)) >= 0)
                {
                    // remove user from list of followed users and shift the remaining users over
                    for (int i = idolIndex; i < loggedInUsers[userIndex].numIdols - 1; i++)
                    {
                        loggedInUsers[userIndex].folllowedIdolIDs[i] = loggedInUsers[userIndex].folllowedIdolIDs[i + 1];
                    }
                    // decerement followed idols by 1
                    loggedInUsers[userIndex].numIdols -= 1;

                    sprintf(lodiResponseMsg.message, "Successfully Unollowed User: %d", lodiClientMsg.recipientID);
                }
                else
                {
                    sprintf(lodiResponseMsg.message, "Couldn't follow User: %d, not found in list of followed idols", lodiClientMsg.recipientID);
                }
            }
            else
            {
                sprintf(lodiResponseMsg.message, "User: %d not logged in", lodiClientMsg.userID);
            }

            lodiResponseMsgSize = sizeof(lodiResponseMsg);

            // send ack
            if (send(connectToClientSock, (void *)&lodiResponseMsg, lodiResponseMsgSize, 0) != lodiResponseMsgSize)
                DieWithError("[Lodi_Server] Acknowlegement message failed to send");
            // todo change result to reflect the actual result
            printf("[Lodi_Server] Response -> Ack Message: User: %d %s\n", lodiClientMsg.userID, lodiResponseMsg.message);
            break;
        case logout:
            // logout
            // server updates logged in users. list of followed idols should stay
            if ((userIndex = findUser(lodiClientMsg.userID)) >= 0)
            {
                // set logged in status to false
                loggedInUsers[userIndex].signedIn = 0;
                printf("[Lodi_Server] User: %d Logged out\n", lodiClientMsg.userID);

                // send logout acknowlegment to client
                //  create message
                memset(&lodiResponseMsg, 0, sizeof(lodiResponseMsg));
                lodiResponseMsg.messageType = ackLogout;
                lodiResponseMsg.userID = lodiClientMsg.userID;
                sprintf(lodiResponseMsg.message, "User: %d successfully logged out\n", lodiClientMsg.userID);
                lodiResponseMsgSize = sizeof(lodiResponseMsg);

                // send a message back
                if (send(connectToClientSock, (void *)&lodiResponseMsg, lodiResponseMsgSize, 0) != lodiResponseMsgSize)
                    DieWithError("[Lodi_Server] Acknowlegement message failed to send");
                printf("[Lodi_Server] Response -> Ack Lougout to Lodi Client for user: %d\n", lodiClientMsg.userID);
            }
            else
            {
                printf("[Lodi_Server] User to be logged out not found\n");
            }
            break;
        default:
            printf("[Lodi_Server] Recieved <- Invalid message type\n");
            break;
        }
        close(connectToClientSock);
        printLoggedInUsers(loggedInUsers, numUsers);
    }
}

// should be very similar to the recieve portion of sendMessage on the client side
PClientToLodiServer recvFromClient(int tcpSock)
{
    PClientToLodiServer messageBuffer; // buffer for incomint message
    int totalBytesRcvd, bytesRcvd;

    totalBytesRcvd = 0;
    while (totalBytesRcvd < sizeof(messageBuffer))
    {
        // accumulate up to the buffer size
        if ((bytesRcvd = recv(tcpSock, ((char *)&messageBuffer) + totalBytesRcvd, sizeof(messageBuffer) - totalBytesRcvd, 0)) <= 0)
            DieWithError("recv() failed or connection closed prematurely");
        totalBytesRcvd += bytesRcvd; /* Keep tally of total bytes */
    }
    // may or may not need to close at the end of this function

    return messageBuffer;
}

int findUser(int userID)
{
    for (int i = 0; i < numUsers; i++)
    {
        if (userID == loggedInUsers[i].userID)
        {
            return i;
        }
    }
    printf("returning %d", -1);
    return -1;
}

int findIdol(int idolID, unsigned int listIdols[], int numIdols)
{
    for (int i = 0; i < numIdols; i++)
    {
        if (idolID == listIdols[i])
        {
            return i;
        }
    }
    return -1;
}

// print out all users currently signed in
void printLoggedInUsers(UserSignInStatus usersList[], int numUsers)
{
    printf("[Lodi_Server] currently logged in users:\n");
    for (int i = 0; i < numUsers; i++)
    {
        printf("ID: %d logged in:", usersList[i].userID);
        if (usersList[i].signedIn)
            printf("yes\n");
        else
            printf("no\n");
    }
}

void getFeed(int userID)
{
    //zero out buffers
    numInFeed = 0;
    memset(userFeed, 0, sizeof(userFeed));
    UserSignInStatus user = loggedInUsers[findUser(userID)];

    //for each idol user is following find their messages
    for(int i = 0; i < user.numIdols; i++) {
        for (int j = 0; j < numMessages; j++) {
            if(messages[j].userID == user.folllowedIdolIDs[i])
            {
                userFeed[numInFeed] = messages[j];
                numInFeed++;
            }
        } 
    }
}