/*lodi_client.c*/
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

#define LODI_DEFAULT_IP "127.0.0.1"
#define LODI_DEFAULT_PORT 5050
#define PKE_DEFAULT_IP "127.0.0.1"
#define PKE_DEFAULT_PORT 5052

int main(int argc, char *argv[]) // argc counts the arguments and argv contains them
{
    // initialize variables adapted from example code
    struct sockaddr_in fromAddr; // buffer for recieved messages
    unsigned int fromSize;       // the size of the address for recvfrom() (may need to change this to be seperate for each server)
    unsigned int userID;

    // PKE variables
    int pkeSock;                           // socket (not sure if singular or one needed for each server used)
    struct sockaddr_in pkeServAddr;        // pke server address
    unsigned short pkeServPort;            // pke server port
    char *pkeServIP;                       // the ip address of the server
    TOPKServer registerKeyMessage;         // message to send to pke server
    FromPKServer ackRegisterKeyMessage;    // buffer for response from PKE server
    unsigned int ackRegSize;               // size of the ackRegisterKey message

    // Lodi Server variables
    int lodiSock;                               // socket (not sure if singular or one needed for each server used)
    struct sockaddr_in lodiServAddr;            // lodi server address
    unsigned short lodiServPort;                // lodi server port
    char *lodiServIP;                           // ip of lodi server
    PClientToLodiServer loginMessage;           // message to Lodi server
    LodiServerToLodiClientAcks ackLoginMessage; // buffer for response from lodi server
    unsigned int ackLoginSize;                  // length of the acknowlegment message

    // test for correct number of arguments
    // if ((argc < 3) || (argc > 3))
    // {
    //     fprintf(stderr, "Usage: %s <Lodi Server IP> [<Lodi Server Port>]\n", argv[0]);
    //     exit(1);
    // }

    // get user ID
    printf("[Lodi_Client] Please enter user ID: \n");
    scanf("%u", &userID);

    // compute public and private keys
    // private key and public key are flipped from rsa slides. In slides public key encrypts and private key decrypts.
    unsigned int privateKey = computePrivateKey(phiN);
    unsigned int publicKey = computePublicKey(privateKey, phiN);
    printf("[Lodi_Client] computed private key: %d\n", privateKey);
    printf("[Lodi_Client]computed public key: %d\n", publicKey);

    // Create a datagram/UDP socket
    if ((lodiSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");

    // register public key with PKE server

    // submit users public key to PKE server
    // get ip from keyboard
    // printf("Enter IP for Primary Key Server: \n");
    // scanf("%15s", pkeServIP);

    // get the server port
    // printf("Enter port for Primary Key Server: \n");
    // scanf("%hu", &pkeServPort);

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
    if (sendto(lodiSock, (void *)&registerKeyMessage, sizeof(registerKeyMessage), 0,
               (struct sockaddr *)&pkeServAddr, sizeof(pkeServAddr)) != sizeof(registerKeyMessage))
        DieWithError("sendto() sent a different number of bytes than expected");
    printf("[Lodi_Client] Register public key: %u -> PKE server\n", publicKey);

    // recieve acknowlegement from pke server
    fromSize = sizeof(fromAddr);
    ackRegSize = sizeof(ackRegistrerKey);
    memset(&ackRegisterKeyMessage, 0, ackRegSize); // zero out structure

    if ((ackRegSize = recvfrom(lodiSock, (void *)&ackRegisterKeyMessage, ackRegSize, 0,
                               (struct sockaddr *)&fromAddr, &fromSize)) < 0)
        DieWithError("Login Acknowlegement from the server failed.");

    // check that response came from correct server
    if (pkeServAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr)
        DieWithError("Packet from unknown source");
    printf("[Lodi_Client] response <- PKE Server user: %u \n", ackRegisterKeyMessage.publicKey);

    printf("[Lodi_Client] Press enter to continue after tfa is opened\n");
    getchar();
    getchar();

    // Perform authentication process with Lodi Server

    // set ip for lodi server
    lodiServIP = LODI_DEFAULT_IP;
    // set server port
    lodiServPort = LODI_DEFAULT_PORT;

    // set message varriables
    memset(&loginMessage, 0, sizeof(loginMessage));
    loginMessage.messageType = login;
    loginMessage.userID = userID;
    loginMessage.recipientID = 0;
    unsigned long currentTime = reduceInput((long)time(NULL));
    loginMessage.timestamp = currentTime;
    unsigned long digitalSig = rsaEncrypt(currentTime, privateKey); 
    loginMessage.digitalSig = digitalSig;

    // set lodi server address structure
    memset(&lodiServAddr, 0, sizeof(lodiServAddr));       // zero out structure
    lodiServAddr.sin_family = AF_INET;                    // Internet addr family
    lodiServAddr.sin_addr.s_addr = inet_addr(lodiServIP); // lodi server ip
    lodiServAddr.sin_port = htons(lodiServPort);          // lodi server port

    // send login request to Lodi Server
    if (sendto(lodiSock, (void *)&loginMessage, sizeof(loginMessage), 0, (struct sockaddr *)&lodiServAddr, sizeof(lodiServAddr)) != sizeof(loginMessage))
        DieWithError("sendto() sent a different number of bytes than expected");
    printf("[Lodi_Client] Request Login -> User: %d, Current time: %hu, Digital Signature: %hu to lodi server\n", userID, currentTime, digitalSig);

    // Recieve the response
    fromSize = sizeof(fromAddr);
    ackLoginSize = sizeof(ackLoginMessage);
    memset(&ackLoginMessage, 0, ackLoginSize); // zero out structure

    if ((ackLoginSize = recvfrom(lodiSock, (void *)&ackLoginMessage, ackLoginSize, 0,
                                 (struct sockaddr *)&fromAddr, &fromSize)) < 0)
        DieWithError("Login Acknowlegement from the server failed.");

    // check that response came from correct server
    if (lodiServAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr)
        DieWithError("Packet from unknown source");

    printf("[Lodi_Client] Response -> from Lodi server, Login Successful \n");

    int quit = 1;
    while(quit) {
        printf("[Lodi Client] press 0 to exit\n");
        scanf("%d", &quit);
    }

    // exit
    close(lodiSock);
    exit(0);
}