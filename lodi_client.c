/*lodi_client.c*/
//(most logic based on examples)
#include "lodi_messages.h"
#include "pke_messages.h"
#include "rsa.h"
#include <sys/socket.h> //needed to use socket(), connect(), sendto() and recvfrom()
#include <arpa/inet.h>  // sockaddr and inet_addr()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> //for close
#include <time.h>

void DieWithError(char *errorMessage);
void serverLogin(int userID, unsigned int privateKey);
void serverLogout(int userID);
void makePost(int userID);
void followRequest(int userID);
void unfollowRequest(int userID);
void feedRequest(int userID);

int main(int argc, char *argv[]) // argc counts the arguments and argv contains them
{
    // initialize variables adapted from example code
    // UDP variables for auth
    int udpSock;                    // socket (not sure if singular or one needed for each server used)
    struct sockaddr_in fromAddrUdp; // buffer for recieved messages
    unsigned int fromSizeUdp;       // the size of the address for recvfrom() (may need to change this to be seperate for each server)
    unsigned int userID;

    // PKE variables
    struct sockaddr_in pkeServAddr;     // pke server address
    unsigned short pkeServPort;         // pke server port
    char *pkeServIP;                    // the ip address of the server
    TOPKServer registerKeyMessage;      // message to send to pke server
    FromPKServer ackRegisterKeyMessage; // buffer for response from PKE server
    unsigned int ackRegSize;            // size of the ackRegisterKey message

    // change to work with tcp
    int loggedIn; // boolean value for whether or not the usser is currently logged in.

    // get user ID
    printf("[Lodi_Client] Please enter user ID: \n");
    scanf("%u", &userID);

    // compute public and private keys
    // private key and public key are flipped from rsa slides. In slides public key encrypts and private key decrypts.
    unsigned int privateKey = computePrivateKey(phiN);
    unsigned int publicKey = computePublicKey(privateKey, phiN);
    printf("[Lodi_Client] computed private key: %d\n", privateKey);
    printf("[Lodi_Client] computed public key: %d\n", publicKey);

    // Create a datagram/UDP socket
    if ((udpSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("[Lodi_Client] socket() failed");

    // set ip and port for pke server
    pkeServIP = PKE_DEFAULT_IP;
    pkeServPort = PKE_DEFAULT_PORT;

    // set message values
    memset(&registerKeyMessage, 0, sizeof(registerKeyMessage));
    registerKeyMessage.messageType = registerKey;
    registerKeyMessage.publicKey = publicKey;
    registerKeyMessage.userID = userID;

    // set PKE server address structure
    memset(&pkeServAddr, 0, sizeof(pkeServAddr));
    pkeServAddr.sin_family = AF_INET;
    pkeServAddr.sin_addr.s_addr = inet_addr(pkeServIP);
    pkeServAddr.sin_port = htons(pkeServPort);

    // send primary key to pke server
    if (sendto(udpSock, (void *)&registerKeyMessage, sizeof(registerKeyMessage), 0,
               (struct sockaddr *)&pkeServAddr, sizeof(pkeServAddr)) != sizeof(registerKeyMessage))
        DieWithError("[Lodi_Client] sendto() sent a different number of bytes than expected");
    printf("[Lodi_Client] Register -> public key: %u with PKE server\n", publicKey);

    // recieve acknowlegement from pke server
    fromSizeUdp = sizeof(fromAddrUdp);
    ackRegSize = sizeof(ackRegisterKeyMessage);
    memset(&ackRegisterKeyMessage, 0, ackRegSize); // zero out structure

    if ((ackRegSize = recvfrom(udpSock, (void *)&ackRegisterKeyMessage, ackRegSize, 0,
                               (struct sockaddr *)&fromAddrUdp, &fromSizeUdp)) < 0)
        DieWithError("[Lodi_Client] Login Acknowlegement from the server failed.");

    // check that response came from correct server
    if (pkeServAddr.sin_addr.s_addr != fromAddrUdp.sin_addr.s_addr)
        DieWithError("[Lodi_Client] Packet from unknown source");
    printf("[Lodi_Client] Response <- PKE Server Public Key: %u\n", ackRegisterKeyMessage.publicKey);

    // expanded menu to include menu options.
    loggedIn = 0;   // initialize login value to false
    int option = 9; // default to 9 because it's not an option on the list
    while (option)
    {
        printf("[Lodi Client] select an option:\n");
        if (loggedIn)
        {
            printf("1. Make Post\n");
            printf("2. Request Feed\n");
            printf("3. Follow an Idol\n");
            printf("4. Unfollow an Idol\n");
            printf("5. Logout\n");
            printf("0. Quit\n");

            scanf("%d", &option);

            switch (option)
            {
            case 1:
                makePost(userID);
                break;
            case 2:
                //request feed of messages from followed idols
                feedRequest(userID);
                break;
            case 3:
                followRequest(userID);
                break;
            case 4:
                unfollowRequest(userID);
                break;
            case 5:
                serverLogout(userID);
                loggedIn = 0;
                break;
            case 0:
                serverLogout(userID);
                break;
            default:
                printf("[Lodi Client] invalid output try again");
            }
        }
        else
        {
            printf("1. Login\n");
            printf("0. Quit\n");

            scanf("%d", &option);

            switch (option)
            {
            case 1: // login
                serverLogin(userID, privateKey);
                loggedIn = 1;
                break;
            case 0:
                break;
            }
        }
    }

    // exit
    close(udpSock);
    exit(0);
}

//creates the tcp sock, connects to server, sends and recieves messages, prints out results
LodiServerMessage sendMessage(PClientToLodiServer message)
{
    int tcpSock;

    // Lodi Server variables
    struct sockaddr_in lodiServAddr; // lodi server address
    unsigned short lodiServPort;     // lodi server port
    char *lodiServIP;                // ip of lodi server
    LodiServerMessage ackBuffer;     // buffer for response from lodi server
    // unsigned int ackBufferSize;                  // length of the acknowlegment message

    lodiServIP = LODI_DEFAULT_IP;     // set ip for lodi server
    lodiServPort = LODI_DEFAULT_PORT; // set server port

    // set lodi server address structure
    memset(&lodiServAddr, 0, sizeof(lodiServAddr));       // zero out structure
    lodiServAddr.sin_family = AF_INET;                    // Internet addr family
    lodiServAddr.sin_addr.s_addr = inet_addr(lodiServIP); // lodi server ip
    lodiServAddr.sin_port = htons(lodiServPort);          // lodi server port

    static const char *mTypes[] = {"login", "post", "feed", "follow", "unfollow", "logout"}; // allows printing of the message type
    static const char *ackTypes[] = {"ackLogin", "ackPost", "ackFeed", "ackFollow", "ackUnfollow", "ackLogout", "feedMessage"};
    int bytesRcvd, totalBytesRcvd; // bytes recieved in a single recv() and total bytes recieved

    /* Create a reliable, stream socket using TCP */
    if ((tcpSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        DieWithError("socket() failed");

    /* Establish the connection to the echo server */
    if (connect(tcpSock, (struct sockaddr *)&lodiServAddr, sizeof(lodiServAddr)) < 0)
        DieWithError("connect() failed");

    // send message
    if (send(tcpSock, &message, sizeof(message), 0) != sizeof(message))
        DieWithError("send() sent a different number of bytes than expected");
    printf("[Lodi_Client] Request -> Type: %s User: %d\n", mTypes[message.messageType], message.userID);

    totalBytesRcvd = 0;
    while (totalBytesRcvd < sizeof(ackBuffer))
    {
        // accumulate up to the buffer size
        if ((bytesRcvd = recv(tcpSock, ((char *)&ackBuffer) + totalBytesRcvd, sizeof(ackBuffer) - totalBytesRcvd, 0)) <= 0)
            DieWithError("recv() failed or connection closed prematurely");
        totalBytesRcvd += bytesRcvd; /* Keep tally of total bytes */
    }
    printf("[Lodi_Client] Response <- Ack Type: %s User: %d message %s\n", ackTypes[ackBuffer.messageType], ackBuffer.userID, ackBuffer.message);

    //recieve the message feed if nessesary
    if (ackBuffer.messageType == ackFeed) {
    LodiServerMessage feedBuffer;
    int totalBytesRcvd, bytesRcvd;
    for (int i = 0; i < ackBuffer.next; i++)
    {
        memset(&feedBuffer, 0, sizeof(feedBuffer));
        totalBytesRcvd = 0;
        while (totalBytesRcvd < sizeof(feedBuffer))
        {
            // accumulate up to the buffer size
            if ((bytesRcvd = recv(tcpSock, ((char *)&feedBuffer) + totalBytesRcvd, sizeof(feedBuffer) - totalBytesRcvd, 0)) <= 0)
                DieWithError("recv() failed or connection closed prematurely");
            totalBytesRcvd += bytesRcvd; /* Keep tally of total bytes */
        }
        printf("Idol: %u Message: %s\n", feedBuffer.userID, feedBuffer.message);
    }
    }

    // close connection
    close(tcpSock);
    return ackBuffer;
}

//sends login request
void serverLogin(int userID, unsigned int privateKey)
{
    PClientToLodiServer loginMessage; // message to send to Lodi server

    // set message varriables
    memset(&loginMessage, 0, sizeof(loginMessage));
    loginMessage.messageType = login;
    loginMessage.userID = userID;
    loginMessage.recipientID = 0;
    unsigned long currentTime = reduceInput((long)time(NULL));
    loginMessage.timestamp = currentTime;
    unsigned long digitalSig = rsaEncrypt(currentTime, privateKey);
    loginMessage.digitalSig = digitalSig;

    sendMessage(loginMessage);
}

//sends logout request
void serverLogout(int userID)
{
    PClientToLodiServer logoutMessage;

    memset(&logoutMessage, 0, sizeof(logoutMessage));
    logoutMessage.messageType = logout;
    logoutMessage.userID = userID;

    sendMessage(logoutMessage);
}

//prompts user for post and sends the post to the server
void makePost(int userID)
{
    PClientToLodiServer postMessage;

    memset(&postMessage, 0, sizeof(postMessage));
    postMessage.messageType = post;
    postMessage.userID = userID;

    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;

    printf("enter text < 100 characters to post: \n");
    fgets(postMessage.message, 99, stdin);

    sendMessage(postMessage);
}

//asks user for id and sends follow request
void followRequest(int userID)
{
    PClientToLodiServer followMessage;

    memset(&followMessage, 0, sizeof(followMessage));
    followMessage.messageType = follow;
    followMessage.userID = userID;
    printf("enter id of user to follow: \n");
    scanf("%u", &followMessage.recipientID);

    sendMessage(followMessage);
}

//asks user for id and sends unfollow request
void unfollowRequest(int userID)
{
    PClientToLodiServer followMessage;

    memset(&followMessage, 0, sizeof(followMessage));
    followMessage.messageType = unfollow;
    followMessage.userID = userID;
    printf("enter id of user to unfollow: \n");
    scanf("%u", &followMessage.recipientID);

    sendMessage(followMessage);
}

//requests the message feed
void feedRequest(int userID)
{
    PClientToLodiServer feedMessage;
    memset(&feedMessage, 0, sizeof(feedMessage));
    feedMessage.messageType = feed; // the server will send the number of messages in feed to expect
    feedMessage.userID = userID;

    sendMessage(feedMessage);
}
