/*lodi_client.c*/
//Primary Dev Patrick Martus
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
void serverLogin(int userID, unsigned int privateKey, int tcpSock);

int main(int argc, char *argv[]) // argc counts the arguments and argv contains them
{
    // initialize variables adapted from example code
    //UDP variables for auth
    int udpSock;                // socket (not sure if singular or one needed for each server used)
    struct sockaddr_in fromAddrUdp; // buffer for recieved messages
    unsigned int fromSizeUdp;       // the size of the address for recvfrom() (may need to change this to be seperate for each server)
    unsigned int userID;

    // PKE variables
    struct sockaddr_in pkeServAddr;        // pke server address
    unsigned short pkeServPort;            // pke server port
    char *pkeServIP;                       // the ip address of the server
    TOPKServer registerKeyMessage;         // message to send to pke server
    FromPKServer ackRegisterKeyMessage;    // buffer for response from PKE server
    unsigned int ackRegSize;               // size of the ackRegisterKey message

    //todo change to work with tcp
    int tcpSock;

    

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

    //set ip and port for pke server
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

    /* Create a reliable, stream socket using TCP */
    if ((tcpSock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        DieWithError("socket() failed");

    //todo new menu negates the need for this most likely
    printf("[Lodi_Client] Press enter to continue after tfa is opened\n");
    getchar();
    getchar();

    //TODO change to tcp

    // // send login request to Lodi Server
    // if (sendto(udpSock, (void *)&loginMessage, sizeof(loginMessage), 0, (struct sockaddr *)&lodiServAddr, sizeof(lodiServAddr)) != sizeof(loginMessage))
    //     DieWithError("[Lodi_Client] sendto() sent a different number of bytes than expected");
    // printf("[Lodi_Client] Request -> Login User: %u, Current time: %lu, Digital Signature: %lu to lodi server\n", userID, currentTime, digitalSig);

    // // Recieve the response
    // fromSizeUdp = sizeof(fromAddrUdp);
    // ackLoginSize = sizeof(ackBuffer);
    // memset(&ackBuffer, 0, ackLoginSize); // zero out structure

    // if ((ackLoginSize = recvfrom(udpSock, (void *)&ackBuffer, ackLoginSize, 0,
    //                              (struct sockaddr *)&fromAddrUdp, &fromSizeUdp)) < 0)
    //     DieWithError("[Lodi_Client] Login Acknowlegement from the server failed.");

    // // check that response came from correct server
    // if (lodiServAddr.sin_addr.s_addr != fromAddrUdp.sin_addr.s_addr)
    //     DieWithError("[Lodi_Client] Packet from unknown source");

    // printf("[Lodi_Client] Response <- from Lodi server, Login Successful \n");

    //todo expand menu to include menu options.
    int option = 9; //default to 9 because it's not an option on the list
    while(option) {
        printf("[Lodi Client] select an option:\n");
        printf("1. Login\n");
        printf("2. Make Post\n");
        printf("3. Request Feed\n");
        printf("4. Follow an Idol\n");
        printf("5. Unfollow an Idol\n");
        printf("6. Logout\n");
        printf("0. Quit\n");

        scanf("%d", &option);

        switch(option) {
            case 1:
                serverLogin(userID, privateKey, tcpSock);
                break;
            case 2:
                //TODO post
                break;
            case 3:
                //TODO request feed of messages from followed idols
                break;
            case 4:
                //TODO follow an idol
                break;
            case 5:
                //TODO unfollow an idol
                break;
            case 6:
                //TODO logout
                break;
            case 0:
                //TODO Quit
                //should logout as well
                break;
            default:
                printf("[Lodi Client] invalid output try again");
        }
    }

    // exit
    close(udpSock);
    exit(0);
}

LodiServerMessage sendMessage(int tcpSock, PClientToLodiServer message) {
    // Lodi Server variables
    struct sockaddr_in lodiServAddr;            // lodi server address
    unsigned short lodiServPort;                // lodi server port
    char *lodiServIP;                           // ip of lodi server
    LodiServerMessage ackBuffer;                // buffer for response from lodi server
    unsigned int ackBufferSize;                  // length of the acknowlegment message

    lodiServIP = LODI_DEFAULT_IP;                         // set ip for lodi server
    lodiServPort = LODI_DEFAULT_PORT;                     // set server port

    // set lodi server address structure
    memset(&lodiServAddr, 0, sizeof(lodiServAddr));       // zero out structure
    lodiServAddr.sin_family = AF_INET;                    // Internet addr family
    lodiServAddr.sin_addr.s_addr = inet_addr(lodiServIP); // lodi server ip
    lodiServAddr.sin_port = htons(lodiServPort);          // lodi server port

    static const char *mTypes[] = {"login", "post", "feed", "follow", "unfollow", "logout"}; //allows printing of the message type
    static const char *ackTypes[] = {"ackLogin", "ackPost", "ackFeed", "ackFollow", "ackUnfollow", "ackLogout", "feedMessage"};
    int bytesRcvd, totalBytesRcvd;              //bytes recieved in a single recv() and total bytes recieved

    /* Establish the connection to the echo server */
    if (connect(tcpSock, (struct sockaddr *) &lodiServAddr, sizeof(lodiServAddr)) < 0)
        DieWithError("connect() failed");

    //send message
    if (send(tcpSock, &message, sizeof(message), 0) != sizeof(message))
        DieWithError("send() sent a different number of bytes than expected");
    printf("[Lodi_Client] Request -> Type: %s User: %d\n", mTypes[message.messageType], message.userID);
    
    totalBytesRcvd = 0;
    while (totalBytesRcvd < sizeof(ackBuffer))
    {
        //accumulate up to the buffer size
        if ((bytesRcvd = recv(tcpSock, ((char *)&ackBuffer) + totalBytesRcvd, sizeof(ackBuffer) - totalBytesRcvd, 0)) <= 0)
            DieWithError("recv() failed or connection closed prematurely");
        totalBytesRcvd += bytesRcvd;   /* Keep tally of total bytes */
    }
    printf("[Lodi_Client] Response <- Ack Type: %s User: %d\n", ackTypes[ackBuffer.messageType], ackBuffer.userID);
    return ackBuffer;
}

void serverLogin(int userID, unsigned int privateKey, int tcpSock) {
    PClientToLodiServer loginMessage;           // message to send to Lodi server
    
    // set message varriables
    memset(&loginMessage, 0, sizeof(loginMessage));
    loginMessage.messageType = login;
    loginMessage.userID = userID;
    loginMessage.recipientID = 0;
    unsigned long currentTime = reduceInput((long)time(NULL));
    loginMessage.timestamp = currentTime;
    unsigned long digitalSig = rsaEncrypt(currentTime, privateKey); 
    loginMessage.digitalSig = digitalSig;

    sendMessage(tcpSock, loginMessage);
    
}