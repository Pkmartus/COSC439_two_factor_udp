#include "tfa_messages.h"
#include "rsa.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>

void DieWithError(char *errorMessage);

#define RECV_TIMEOUT_MS 2500
#define MAX_REG_RETRIES 3


static void ip_to_str(struct sockaddr_in *addr, char *buf, size_t len) {
    inet_ntop(AF_INET, &(addr->sin_addr), buf, len);
}

int main(int argc, char *argv[])
{
    // get user ID
    unsigned int userID;
    printf("please enter user ID: \n");
    scanf("%u", &userID);

    // setup the ip and ports
    const char *tfaServIP = TFA_DEFAULT_IP;
    unsigned short tfaServPort = TFA_DEFAULT_PORT;

    /* ---- Socket + bind ---- */
    int servSock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (servSock < 0)
        DieWithError("socket() failed");

    /* ---- TFA server address ---- */
    struct sockaddr_in tfaServAddr;
    memset(&tfaServAddr, 0, sizeof(tfaServAddr));
    tfaServAddr.sin_family = AF_INET;
    tfaServAddr.sin_addr.s_addr = inet_addr(tfaServIP);
    tfaServAddr.sin_port = htons(tfaServPort);

    printf("[TFA_CLIENT] user=%u TFA server port: %hu\n", userID, tfaServPort);

    // /* ---- Compute RSA keys (same style as lodi_client) ---- */
    unsigned int privateKey = computePrivateKey(phiN); // not sure if we should be computing this again here or somehow get it from client but we can worry about that in project 2

    /* ---- Registration 3-way handshake ---- */
    int attempt;
    for (attempt = 1; attempt <= MAX_REG_RETRIES; ++attempt)
    {
        TFAClientOrLodiServerToTFAServer regPK;
        memset(&regPK, 0, sizeof(regPK));
        regPK.messageType = registerTFA;
        regPK.userID = userID;

        // create digital signature
        unsigned long nowTs = reduceInput((unsigned long)time(NULL));
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
            printf("[TFA_CLIENT] -> registerTFA user=%u ts=%lu sig=%lu to port: %hu\n",
                   regPK.userID, regPK.timeStamp, regPK.digitalSig, tfaServPort);
        }
        /* Wait for confirmTFA */
        TFAServerToTFAClient confirm;
        memset(&confirm, 0, sizeof(confirm));
        struct sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);
        ssize_t n = recvfrom(servSock, &confirm, sizeof(confirm), 0,
                             (struct sockaddr *)&fromAddr, &fromLen);
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                printf("[TFA_CLIENT] (timeout) waiting for confirmTFA, retrying...\n");
                //continue; /* try again */
            }
            else
            {
                perror("[TFA_CLIENT] recvfrom(confirmTFA) failed");
                //continue;
            }
        }
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
            printf("[TFA_CLIENT] -> ackRegTFA user=%u to port: %hu\n", userID, tfaServPort);
        }

        /* Registration complete */
        break;
    }

    if (attempt > MAX_REG_RETRIES)
    {
        printf("[TFA_CLIENT] Registration failed after %d attempts\n", MAX_REG_RETRIES);
        /* Keep running if you want, but commonly we exit here */
        close(servSock);
        return 1;
    }

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
        if (n < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                /* idle wait; keep listening */
                continue;
            }
            perror("[TFA_CLIENT] recvfrom(pushTFA) failed");
            continue;
        }
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

        printf("[TFA_CLIENT] <- pushTFA user=%u from port: %d\n", push.userID, tfaServPort);

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
        printf("[TFA_CLIENT] -> ackPushTFA user=%u to port: %d\n", userID, tfaServPort);
    }

    /* not reached */
    close(servSock);
    return 0;
}
