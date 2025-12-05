#include "pke_messages.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>

void DieWithError(char *errorMessage);

#define MAX_ENTRIES 20
#define RECV_TIMEOUT_MS 2500

static void set_recv_timeout(int sock, int ms) {
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static int find_user_index(unsigned int *ids, unsigned int count, unsigned int userID) {
    for (unsigned int i = 0; i < count; ++i) {
        if (ids[i] == userID) return (int)i;
    }
    return -1;
}

int main(int argc, char *argv[]) {
    int sock = -1;
    unsigned short port = PKE_DEFAULT_PORT;

    if (argc == 2) {
        port = (unsigned short)atoi(argv[1]);
        if (port == 0) {
            fprintf(stderr, "[PKE_SERVER] Invalid port: %s\n", argv[1]);
            return 1;
        }
    } else if (argc != 1) {
        fprintf(stderr, "Usage: %s [<port>]\n", argv[0]);
        return 1;
    }

    /* Socket + bind */
    if ((sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        DieWithError("socket() failed");
    }
    set_recv_timeout(sock, RECV_TIMEOUT_MS);

    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port        = htons(port);

    if (bind(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        DieWithError("bind() failed");
    }

    printf("[PKE_SERVER] Listening on %s:%hu\n",PKE_DEFAULT_IP, port);

    /* In-memory directory */
    unsigned int registeredUserIds[MAX_ENTRIES];
    unsigned int registeredPublicKeys[MAX_ENTRIES];
    unsigned int count = 0;
    memset(registeredUserIds, 0, sizeof(registeredUserIds));
    memset(registeredPublicKeys, 0, sizeof(registeredPublicKeys));

    /* Main loop */
    for (;;) {
        TOPKServer req;
        memset(&req, 0, sizeof(req));

        struct sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);
        ssize_t n = recvfrom(sock, &req, sizeof(req), 0,
                             (struct sockaddr *)&fromAddr, &fromLen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* idle timeout: keep serving */
                continue;
            }
            perror("[PKE_SERVER] recvfrom() failed");
            continue;
        }
        if ((size_t)n != sizeof(req)) {
            char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &fromAddr.sin_addr, ip, sizeof(ip));
            printf("[PKE_SERVER] Ignoring short/long packet (%zd bytes) from %s:%hu\n",
                   n, ip, ntohs(fromAddr.sin_port));
            continue;
        }

        char ip[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &fromAddr.sin_addr, ip, sizeof(ip));

        FromPKServer resp;
        memset(&resp, 0, sizeof(resp));
        resp.userID = req.userID;

        switch (req.messageType) {
            case registerKey: {
                /* Upsert userID -> publicKey */
                int idx = find_user_index(registeredUserIds, count, req.userID);
                if (idx >= 0) {
                    unsigned int old = registeredPublicKeys[idx];
                    registeredPublicKeys[idx] = req.publicKey;
                    printf("[PKE_SERVER] UPDATE user=%u key=0x%u (old=0x%u) from %s:%hu\n",
                           req.userID, req.publicKey, old, ip, ntohs(fromAddr.sin_port));
                } else if (count < MAX_ENTRIES) {
                    registeredUserIds[count] = req.userID;
                    registeredPublicKeys[count] = req.publicKey;
                    ++count;
                    printf("[PKE_SERVER] REGISTER user=%u key=0x%u from %s:%hu\n",
                           req.userID, req.publicKey, ip, ntohs(fromAddr.sin_port));
                } else {
                    /* Table full: keep behavior simple—reject silently or log */
                    printf("[PKE_SERVER] TABLE FULL, cannot register user=%u from %s:%hu\n",
                           req.userID, ip, ntohs(fromAddr.sin_port));
                    /* Still reply with ack to keep caller unblocked */
                }

                resp.messageType = ackRegistrerKey; /* matches header enum spelling */
                resp.publicKey   = req.publicKey;

                if (sendto(sock, &resp, sizeof(resp), 0,
                           (struct sockaddr *)&fromAddr, fromLen) != sizeof(resp)) {
                    perror("[PKE_SERVER] sendto(ackRegistrerKey) failed");
                }
                break;
            }

            case requestKey: {
                /* Lookup userID */
                int idx = find_user_index(registeredUserIds, count, req.userID);
                unsigned int key = (idx >= 0) ? registeredPublicKeys[idx] : 0;

                printf("[PKE_SERVER] REQUEST user=%u -> key=0x%X from %s:%hu\n",
                       req.userID, key, ip, ntohs(fromAddr.sin_port));

                resp.messageType = responsePublicKey;
                resp.publicKey   = key;

                if (sendto(sock, &resp, sizeof(resp), 0,
                           (struct sockaddr *)&fromAddr, fromLen) != sizeof(resp)) {
                    perror("[PKE_SERVER] sendto(responsePublicKey) failed");
                }
                break;
            }

            default: {
                printf("[PKE_SERVER] Unknown messageType=%d from %s:%hu (ignored)\n",
                       req.messageType, ip, ntohs(fromAddr.sin_port));
                break;
            }
        }
    }

    /* never reached */
    close(sock);
    return 0;
}
