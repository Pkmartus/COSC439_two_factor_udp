#include "tfa_messages.h"
#include <sys/socket.h> //needed to use socket(), connect(), sendto() and recvfrom()
#include <arpa/inet.h> // sockaddr and inet_addr()
#include <stdlib.h>
#include <string.h>
#include <unistd.h> //for close

void DieWithError(char *errorMessage);

int main(int argc, char *argv[])
{
    //local
    int sock; //socket
    struct sockaddr_in fromAddr; //local address

    //TFA server variables
    struct sockaddr_in tfaServAddr; //tfa server address
    unsigned short tfaServPort; //tfa server port
    char *tfaServIP; //ip of tfa server
    TFAClientOrLodiServerToTFAServer tfaReg; //message to register tfa
    TFAServerToTFAClient tfaConfirm; //buffer for confirmation message
    TFAClientOrLodiServerToTFAServer tfaAckReg; //acknowlegment of registration message
    TFAServerToTFAClient tfaPush; //buffer for push from tfa server
    TFAClientOrLodiServerToTFAServer tfaAckPush; //message to send back to server

    

    //Register UserID and address (ip and port no) with tfa using 3 way handshake

    //respond to PUSH notifications from TFA server
}