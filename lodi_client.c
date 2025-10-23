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
    unsigned int fromSize; //the size of the address for recvfrom()

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
    LodiServerToLodiClientAcks ackLogin; //buffer for response from lodi server
    
    //test for correct number of arguments
    if ((argc < 3) || (argc > 3)) {
        fprintf(stderr, "Usage: %s <Lodi Server IP> [<Lodi Server Port>]\n", argv[0]);
        exit(1);
    }

    // sumit users public key to PKE server

    //Perform authentication process with Lodi Server
    
    //set ip for lodi server 
    lodiServIP = argv[1];
    //set message varriables
    loginMessage.messageType = login;
    loginMessage.userID = 1;
    loginMessage.recipientID = 0;
    long currentTime = (long)time(NULL);
    loginMessage.timestamp = currentTime;
    loginMessage.digitalSig = rsa_encrypt(currentTime);

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

    if (sendto(lodiSock, (void*)&loginMessage, sizeof(loginMessage), 0, (struct sockaddr *)&lodiServAddr, sizeof(lodiServAddr)) != sizeof(loginMessage))
        DieWithError("sendto() sent a different number of bytes than expected");

//exit

}