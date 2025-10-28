/*lodi_client.c*/
#include "lodi_messages.h"
#include "pke_messages.h"
#include "rsa.h"
#include <sys/socket.h> //needed to use socket(), connect(), sendto() and recvfrom()
#include <arpa/inet.h> // sockaddr and inet_addr()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> //for close
#include <time.h>

void DieWithError(char *errorMessage);

int main(int argc, char *argv[]) //argc counts the arguments and argv contains them
{
    //initialize variables adapted from example code
    struct sockaddr_in fromAddr; //local address
    unsigned int fromSize; //the size of the address for recvfrom() (may need to change this to be seperate for each server)

    //PKE variables
    int pkeSock; //socket (not sure if singular or one needed for each server used)
    struct sockaddr_in pkeServAddr; //pke server address
    unsigned short pkeServPort; //pke server port
    char *pkeServIP; //the ip address of the server
    TOPKServer registerKey; //message to send to pke server
    FromPKServer ackRegisterKey; //buffer for response from PKE server

    //Lodi Server variables
    int lodiSock; //socket (not sure if singular or one needed for each server used)
    struct sockaddr_in lodiServAddr; //lodi server address
    unsigned short lodiServPort; //lodi server port
    char *lodiServIP; //ip of lodi server
    PClientToLodiServer loginMessage; //message to Lodi server
    LodiServerToLodiClientAcks ackLoginMessage; //buffer for response from lodi server
    unsigned int ackLoginSize; //length of the acknowlegment message
    
    //test for correct number of arguments
    if ((argc < 3) || (argc > 3)) {
        fprintf(stderr, "Usage: %s <Lodi Server IP> [<Lodi Server Port>]\n", argv[0]);
        exit(1);
    }

    //compute public and private keys
    //come up with 2 large primes p and q
    unsigned int p = 7;
    unsigned int q = 11;
    //compute n from p and q
    long n = p*q;
    //Phi(n)
    long phiN = (p-1)*(q-1);
    //private key and public key are flipped from rsa slides. In slides public key encrypts and private key decrypts.
    long privateKey = computePrivateKey(phiN);
    long publicKey = computePublicKey(privateKey, phiN);

    // sumit users public key to PKE server

    //Perform authentication process with Lodi Server
    
    //set ip for lodi server 
    lodiServIP = argv[1];
    //set message varriables
    memset(&loginMessage, 0, sizeof(loginMessage));
    loginMessage.messageType = login;
    loginMessage.userID = 42;
    loginMessage.recipientID = 0;
    long currentTime = (long)time(NULL);
    loginMessage.timestamp = currentTime;
    loginMessage.digitalSig = rsaEncrypt(currentTime, 5); //temperary hardcoded pk

    //set server port
    lodiServPort = atoi(argv[2]);

    //Create a datagram/UDP socket for Lodi Sever
    if ((lodiSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");
    
    //set lodi server address structure
    memset(&lodiServAddr, 0, sizeof(lodiServAddr)); //zero out structure
    lodiServAddr.sin_family = AF_INET; //Internet addr family
    lodiServAddr.sin_addr.s_addr = inet_addr(lodiServIP); //lodi server ip
    lodiServAddr.sin_port = htons(lodiServPort); //lodi server port

    //send login request to Lodi Server
    if (sendto(lodiSock, (void*)&loginMessage, sizeof(loginMessage), 0, (struct sockaddr *)&lodiServAddr, sizeof(lodiServAddr)) != sizeof(loginMessage))
        DieWithError("sendto() sent a different number of bytes than expected");

    //Recieve the response
    fromSize = sizeof(fromAddr);
    ackLoginSize = sizeof(ackLoginMessage);
    memset(&ackLoginMessage, 0, ackLoginSize); //zero out structure


    if ((ackLoginSize = recvfrom(lodiSock, (void *)&ackLoginMessage, ackLoginSize, 0, 
            (struct sockaddr *)&fromAddr, &fromSize)) < 0)
        DieWithError("Login Acknowlegement from the server failed.");

    //check that response came from correct server
    if(lodiServAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr)
        DieWithError("Packet from unknown source");

    printf("response recieved from server \n");
    
    //exit
    close(lodiSock);
    exit(0);
}