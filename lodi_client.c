#include "lodi_messages.h"
#include "pke_messages.h"
#include <sys/socket.h> //needed to use socket(), connect(), sendto() and recvfrom()
#include <arpa/inet.h> // sockaddr and inet_addr()
#include <stdlib.h>
#include <string.h>
#include <unistd.h> //for close

void DieWithError(char *errorMessage);

int main(int argc, char *argv[]) //argc counts the arguments and argv contains them
{
    //initialize variables adapted from example code
    int sock; //socket (not sure if singular or one needed for each server used)
    struct sockaddr_in fromAddr; //local address

    //PKE variables
    struct sockaddr_in pkeServAddr; //pke server address
    unsigned short pkeServPort; //pke server port
    char *pkeServIP; //the ip address of the server
    TOPKServer registerKey; //message to send to pke server
    FromPKServer ackRegisterKey; //buffer for response from PKE server

    //Lodi Server variables
    struct sockaddr_in lodiServAddr; //lodi server address
    unsigned short lodiServPort; //lodi server port
    char *lodiServIP; //ip of lodi server
    PClientToLodiServer login; //message to Lodi server
    LodiServerToLodiClientAcks ackLogin; //buffer for response from lodi server

    struct sockaddr_in fromAddr; // source address for responses
    unsigned int fromSize; //the size of the address for recvfrom()
    

    





// sumit users public key to PKE server

//Perform authentication process with Lodi Server

//exit

}