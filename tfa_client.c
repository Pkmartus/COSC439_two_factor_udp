#include "tfa_messages.h"
#include "rsa.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
// #include <errno.h>
// #include <time.h>

void DieWithError(char *errorMessage);

// #define RECV_TIMEOUT_MS 2500
// #define MAX_REG_RETRIES 3

// static void set_recv_timeout(int servSock, int ms) {
//     struct timeval tv;
//     tv.tv_sec  = ms / 1000;
//     tv.tv_usec = (ms % 1000) * 1000;
//     (void)setsockopt(servSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
// }

// static void ip_to_str(struct sockaddr_in *addr, char *buf, size_t len) {
//     inet_ntop(AF_INET, &(addr->sin_addr), buf, len);
// }

int main(int argc, char *argv[])
{
    // if we're hardcoding ip and port we might not need arguments
    //  if (argc != 5)
    //  {
    //      fprintf(stderr,
    //              "Usage: %s <userID> <TFA_SERVER_IP> <TFA_SERVER_PORT> <LOCAL_PORT>\n"
    //              "Example: %s 123 127.0.0.1 40002 41002\n",
    //              argv[0], argv[0]);
    //      exit(1);
    //  }

    // get user ID
    unsigned int userID;
    printf("please enter user ID: \n");
    scanf("%u", &userID);

    // setup the ip and ports
    // unsigned int userID = (unsigned int)strtoul(argv[1], NULL, 10);
    const char *tfaServIP = "127.0.0.1";
    unsigned short tfaServPort = 5051; // we'll need to change this before it goes to emunix
    // unsigned short localPort = (unsigned short)strtoul(argv[4], NULL, 10);

    /* ---- Socket + bind ---- */
    int servSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (servSock < 0)
        DieWithError("socket() failed");

    // //address structure for server not local
    // struct sockaddr_in tfaServAddr;
    // memset(&tfaServAddr, 0, sizeof(tfaServAddr));
    // tfaServAddr.sin_family = AF_INET;
    // tfaServAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    // tfaServAddr.sin_port = htons(tfaServPort);

    // if (bind(servSock, (struct sockaddr *)&tfaServAddr, sizeof(tfaServAddr)) < 0)
    // {
    //     DieWithError("bind() failed");
    // }

    /* ---- TFA server address ---- */
    struct sockaddr_in tfaServAddr;
    memset(&tfaServAddr, 0, sizeof(tfaServAddr));
    tfaServAddr.sin_family = AF_INET;
    tfaServAddr.sin_addr.s_addr = inet_addr(tfaServIP);
    tfaServAddr.sin_port = htons(tfaServPort);
    // if (inet_pton(AF_INET, tfaServIP, &tfaServAddr.sin_addr) != 1)
    // {
    //     DieWithError("inet_pton() failed for TFA_SERVER_IP");
    // }

    printf("[TFA_CLIENT] user=%u TFA server %s:%hu\n", userID, tfaServIP, tfaServPort);

    // /* ---- Compute RSA keys (same style as lodi_client) ---- */
    unsigned int privateKey = computePrivateKey(phiN); // not sure if we should be computing this again here or somehow get it from client but we can worry about that in project 2

    /* ---- Registration 3-way handshake ---- */
    // int attempt;
    //  for (attempt = 1; attempt <= MAX_REG_RETRIES; ++attempt) {
    TFAClientOrLodiServerToTFAServer regPK;
    memset(&regPK, 0, sizeof(regPK));
    regPK.messageType = registerTFA;
    regPK.userID = userID;

    // create digital signature
    unsigned long nowTs = (unsigned long)time(NULL);
    regPK.timeStamp = nowTs;
    regPK.digitalSig = rsaEncrypt(nowTs, privateKey);
    ssize_t sent = sendto(servSock, &regPK, sizeof(regPK), 0,
                          (struct sockaddr *)&tfaServAddr, sizeof(tfaServAddr));
    if (sent != sizeof(regPK))
    {
        perror("[TFA_CLIENT] sendto(registerTFA) failed");
        /* retry next loop iteration */
    }
    else
    {
        // printf("[TFA_CLIENT] -> registerTFA user=%u ts=%lu sig=%lu to %s:%hu (attempt %d/%d)\n",
        //        regPK.userID, regPK.timeStamp, regPK.digitalSig, tfaServIP, tfaServPort, attempt, MAX_REG_RETRIES);
        printf("[TFA_CLIENT] -> registerTFA user=%u ts=%lu sig=%lu to %s:%hu\n",
               regPK.userID, regPK.timeStamp, regPK.digitalSig, tfaServIP, tfaServPort);
    }
    /* Wait for confirmTFA */
    TFAServerToTFAClient confirm;
    memset(&confirm, 0, sizeof(confirm));
    struct sockaddr_in fromAddr;
    socklen_t fromLen = sizeof(fromAddr);
    ssize_t n = recvfrom(servSock, &confirm, sizeof(confirm), 0,
                         (struct sockaddr *)&fromAddr, &fromLen);
    // if (n < 0)
    // {
    //     if (errno == EAGAIN || errno == EWOULDBLOCK)
    //     {
    //         printf("[TFA_CLIENT] (timeout) waiting for confirmTFA, retrying...\n");
    //         //continue; /* try again */
    //     }
    //     else
    //     {
    //         perror("[TFA_CLIENT] recvfrom(confirmTFA) failed");
    //         //continue;
    //     }
    // }
    if ((size_t)n != sizeof(confirm))
    {
        printf("[TFA_CLIENT] Ignoring unexpected size %zd for confirmTFA\n", n);
        // continue;
    }
    /* Validate sender and type */
    if (confirm.messageType != confirmTFA)
    {
        printf("[TFA_CLIENT] Unexpected messageType=%d (expected confirmTFA)\n", confirm.messageType);
        // continue;
    }
    if (fromAddr.sin_addr.s_addr != tfaServAddr.sin_addr.s_addr ||
        fromAddr.sin_port != tfaServAddr.sin_port)
    {
        char fromIp[INET_ADDRSTRLEN];
        ip_to_str(&fromAddr, fromIp, sizeof(fromIp));
        printf("[TFA_CLIENT] Ignoring confirm from unknown source %s:%hu\n",
               fromIp, ntohs(fromAddr.sin_port));
        // continue;
    }
    printf("[TFA_CLIENT] <- confirmTFA user=%u from %s:%hu\n",
           confirm.userID, tfaServIP, tfaServPort);
    /* Send ackRegTFA */
    TFAClientOrLodiServerToTFAServer ack;
    memset(&ack, 0, sizeof(ack));
    ack.messageType = ackRegTFA;
    ack.userID = userID; /* timeStamp, digitalSig should be 0 */
    if (sendto(servSock, &ack, sizeof(ack), 0,
               (struct sockaddr *)&tfaServAddr, sizeof(tfaServAddr)) != sizeof(ack))
    {
        perror("[TFA_CLIENT] sendto(ackRegTFA) failed");
        /* Not fatal; proceed to steady-state anyway */
    }
    else
    {
        printf("[TFA_CLIENT] -> ackRegTFA user=%u to %s:%hu\n", userID, tfaServIP, tfaServPort);
    }

    /* Registration complete */
    // break;
    //}

    // if (attempt > MAX_REG_RETRIES) {
    //     printf("[TFA_CLIENT] Registration failed after %d attempts\n", MAX_REG_RETRIES);
    //     /* Keep running if you want, but commonly we exit here */
    //     close(servSock);
    //     return 1;
    // }

    /* ---- Steady-state: handle pushTFA ---- */
    printf("[TFA_CLIENT] Registered. Waiting for pushTFA...\n");

    for (;;)
    {
        TFAServerToTFAClient push;
        memset(&push, 0, sizeof(push));
        struct sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);

        ssize_t n = recvfrom(servSock, &push, sizeof(push), 0,
                             (struct sockaddr *)&fromAddr, &fromLen);
        // if (n < 0)
        // {
        //     if (errno == EAGAIN || errno == EWOULDBLOCK)
        //     {
        //         /* idle wait; keep listening */
        //         continue;
        //     }
        //     perror("[TFA_CLIENT] recvfrom(pushTFA) failed");
        //     continue;
        // }
        if ((size_t)n != sizeof(push))
        {
            printf("[TFA_CLIENT] Ignoring packet of unexpected size: %zd\n", n);
            continue;
        }

        /* Validate sender and type */
        if (fromAddr.sin_addr.s_addr != tfaServAddr.sin_addr.s_addr ||
            fromAddr.sin_port != tfaServAddr.sin_port)
        {
            char fromIp[INET_ADDRSTRLEN];
            ip_to_str(&fromAddr, fromIp, sizeof(fromIp));
            printf("[TFA_CLIENT] Ignoring packet from unknown source %s:%hu\n",
                   fromIp, ntohs(fromAddr.sin_port));
            continue;
        }
        if (push.messageType != pushTFA)
        {
            printf("[TFA_CLIENT] Ignoring unexpected messageType=%d (expect pushTFA)\n", push.messageType);
            continue;
        }
        if (push.userID != userID)
        {
            printf("[TFA_CLIENT] pushTFA for different userID=%u (ours=%u), ignoring\n",
                   push.userID, userID);
            continue;
        }

        printf("[TFA_CLIENT] <- pushTFA user=%u from %s:%hu\n", push.userID, tfaServIP, tfaServIP);

        /* Reply with ackPushTFA */
        TFAClientOrLodiServerToTFAServer ack;
        memset(&ack, 0, sizeof(ack));
        ack.messageType = ackPushTFA;
        ack.userID = userID; /* timeStamp and digitalSig are 0 */
        if (sendto(servSock, &ack, sizeof(ack), 0,
                   (struct sockaddr *)&tfaServAddr, sizeof(tfaServAddr)) != sizeof(ack))
        {
            perror("[TFA_CLIENT] sendto(ackPushTFA) failed");
            continue;
        }
        printf("[TFA_CLIENT] -> ackPushTFA user=%u to %s:%hu\n", userID, tfaServIP, tfaServPort);
    }

    /* not reached */
    close(servSock);
    return 0;
}
