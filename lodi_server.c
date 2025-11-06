/*lodi_server.c*/
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
#include <errno.h>

void DieWithError(char *errorMessage);

#define RECV_TIMEOUT_MS 2500

static void set_recv_timeout(int sock, int ms) {
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int main(int argc, char *argv[])
{
    // local
    int sock; // socket
    struct sockaddr_in lodiServAddr;
    struct sockaddr_in fromAddr;
    socklen_t fromSize;
    unsigned short lodiServerPort;

    // Lodi Client
    struct sockaddr_in lodiClientAddr;          // address
    socklen_t lodiClientAddrLen;                // length of incoming message
    PClientToLodiServer loginRequest;           // buffer for login message
    int loginRequestSize;                       // size of login message
    LodiServerToLodiClientAcks ackLoginMessage; // acknowlegement to be sent to client
    unsigned int ackLoginSize;

    // PKE Server
    struct sockaddr_in pkeServAddr; // pke server address
    unsigned short pkeServPort;     // pke server port
    char pkeServIP[16] = {0};       // ip of PKE server (xxx.xxx.xxx.xxx)
    TOPKServer pkeRequest;          // message to send to pke server
    FromPKServer pkeResponse;       // buffer for response from PKE server
    unsigned int pkeResponseSize;

    // TFA Server
    struct sockaddr_in tfaServAddr;              // tfa server address
    unsigned short tfaServPort;                  // tfa server port
    char tfaServIP[16] = {0};                    // ip of TFA server
    TFAClientOrLodiServerToTFAServer tfaRequest; // message to send to TFA server
    TFAServerToLodiServer tfaResponse;           // buffer for response from TFA server
    unsigned int tfaResponseSize;

    // currently logged in (unused but kept)
    struct sockaddr_in loggedInCLients[20];
    char *userIds[20];
    int publicKeys[20];

    // check correct number of arguments
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <Lodi Server Port>\n", argv[0]);
        exit(1);
    }

    lodiServerPort = (unsigned short)atoi(argv[1]); // first argument is the local port

    // Create datagram UDP Socket
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
        DieWithError("socket() failed");

    set_recv_timeout(sock, RECV_TIMEOUT_MS);

    // Construct local address structure
    memset(&lodiServAddr, 0, sizeof(lodiServAddr));   // zero out memory
    lodiServAddr.sin_family = AF_INET;                // internet address family
    lodiServAddr.sin_addr.s_addr = htonl(INADDR_ANY); // any incoming interfaces
    lodiServAddr.sin_port = htons(lodiServerPort);    // local port

    // bind socket to local address
    if (bind(sock, (struct sockaddr *)&lodiServAddr, sizeof(lodiServAddr)) < 0)
        DieWithError("bind() failed");

    // get PKE/TFA endpoints from keyboard
    printf("Enter IP for Primary Key Server: \n");
    scanf("%15s", pkeServIP);

    printf("Enter port for Primary Key Server: \n");
    scanf("%hu", &pkeServPort);

    printf("Enter IP for Two Factor Server: \n");
    scanf("%15s", tfaServIP);

    printf("Enter port for Two Factor Server: \n");
    scanf("%hu", &tfaServPort);

    // set PKE server address structure
    memset(&pkeServAddr, 0, sizeof(pkeServAddr));
    pkeServAddr.sin_family = AF_INET;
    pkeServAddr.sin_addr.s_addr = inet_addr(pkeServIP);
    pkeServAddr.sin_port = htons(pkeServPort);

    // set TFA server address structure
    memset(&tfaServAddr, 0, sizeof(tfaServAddr));
    tfaServAddr.sin_family = AF_INET;
    tfaServAddr.sin_addr.s_addr = inet_addr(tfaServIP);
    tfaServAddr.sin_port = htons(tfaServPort);

    for (;;) // run forever
    {
        // recieve login request from client
        printf("[LODI_SERVER] waiting for message from clients\n");

        // set size of in/out parameter
        lodiClientAddrLen = sizeof(lodiClientAddr);

        // clear out memory for login request
        loginRequestSize = sizeof(loginRequest);
        memset(&loginRequest, 0, loginRequestSize);

        // block until message recieved (message struct must be cast to void *)
        if ((loginRequestSize = recvfrom(sock, (void *)&loginRequest, loginRequestSize, 0,
                                         (struct sockaddr *)&lodiClientAddr, &lodiClientAddrLen)) < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue; // idle timeout
            DieWithError("recvfrom() failed");
        }

        // (optional) validate message type
        // if (loginRequest.messageType != login) continue;

        // request public key from PKE Server
        memset(&pkeRequest, 0, sizeof(pkeRequest));
        pkeRequest.messageType = requestKey;
        pkeRequest.userID = loginRequest.userID;
        pkeRequest.publicKey = 0;

        if (sendto(sock, (void *)&pkeRequest, sizeof(pkeRequest), 0,
                   (struct sockaddr *)&pkeServAddr, sizeof(pkeServAddr)) != sizeof(pkeRequest))
            DieWithError("sendto() PKE request sent a different number of bytes than expected");

        // recieve response from pke server
        fromSize = sizeof(fromAddr);
        pkeResponseSize = sizeof(pkeResponse);
        memset(&pkeResponse, 0, pkeResponseSize); // zero out structure

        if ((pkeResponseSize = recvfrom(sock, (void *)&pkeResponse, pkeResponseSize, 0,
                                   (struct sockaddr *)&fromAddr, &fromSize)) < 0)
            DieWithError("Receiving Public Key from PKE server failed");

        // check that response came from correct server
        if(pkeServAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr || pkeServAddr.sin_port != fromAddr.sin_port)
            DieWithError("PKE: Packet from unknown source");

        // (optional) validate message type
        // if (pkeResponse.messageType != responsePublicKey) DieWithError("Unexpected PKE messageType");

        printf("[LODI_SERVER] response received from PKE server\n");

        // decrypt signature using returned public key to verify timestamp
        if (rsaDecrypt(loginRequest.digitalSig, pkeResponse.publicKey) != loginRequest.timestamp)
            DieWithError("Signature doesn't match timestamp");

        printf("[LODI_SERVER] Digital signature verified with public key\n");

        // send request to TFA server
        memset(&tfaRequest, 0, sizeof(tfaRequest));
        tfaRequest.messageType = requestAuth;
        tfaRequest.userID = loginRequest.userID;
        tfaRequest.timeStamp = 0;     // per spec: not needed for requestAuth
        tfaRequest.digitalSig = 0;    // per spec: not needed for requestAuth

        if (sendto(sock, (void *)&tfaRequest, sizeof(tfaRequest), 0,
                   (struct sockaddr *)&tfaServAddr, sizeof(tfaServAddr)) != sizeof(tfaRequest))
            DieWithError("sendto() TFA request sent a different number of bytes than expected");

        // wait for response from TFA server (success-only policy)
        fromSize = sizeof(fromAddr);
        tfaResponseSize = sizeof(tfaResponse);
        memset(&tfaResponse, 0, tfaResponseSize); // zero out structure

        if ((tfaResponseSize = recvfrom(sock, (void *)&tfaResponse, tfaResponseSize, 0,
                                   (struct sockaddr *)&fromAddr, &fromSize)) < 0) {
            // timeout or error => treat as failure (no ackLogin)
            perror("[LODI_SERVER] Two Factor Auth failed or timed out");
            continue;
        }

        // check that response came from correct TFA server
        if(tfaServAddr.sin_addr.s_addr != fromAddr.sin_addr.s_addr || tfaServAddr.sin_port != fromAddr.sin_port) {
            perror("[LODI_SERVER] TFA: Packet from unknown source");
            continue;
        }

        // (optional) validate message type
        // if (tfaResponse.messageType != responseAuth) continue;

        // send login acknowlegment to client
        memset(&ackLoginMessage, 0, sizeof(ackLoginMessage));
        ackLoginMessage.messageType = ackLogin;
        ackLoginMessage.userID = loginRequest.userID;
        ackLoginSize = sizeof(ackLoginMessage);

        if (sendto(sock, (void *)&ackLoginMessage, ackLoginSize, 0,
                   (struct sockaddr *)&lodiClientAddr, lodiClientAddrLen) != (int)ackLoginSize)
            DieWithError("Acknowlegement message failed to send");

        printf("[LODI_SERVER] ackLogin sent to client\n");
    }
}
