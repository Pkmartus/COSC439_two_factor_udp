#include "pke_messages.h"
#include "tfa_messages.h"
#include "rsa.h"
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

#define TFA_DEFAULT_IP "127.0.0.1"
#define TFA_DEFAULT_PORT 5051
#define PKE_DEFAULT_IP "127.0.0.1" //will need to change this when we use gcp
#define PKE_DEFAULT_PORT 5052
#define MAX_CLIENTS 20
#define RECV_TIMEOUT_MS 2500
#define ACK_RETRIES 2  /* how many timeout periods we’ll wait for ackPushTFA */

static void set_recv_timeout(int sock, int ms) {
    struct timeval tv;
    tv.tv_sec  = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    (void)setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

// static void ip_to_str(const struct sockaddr_in *addr, char *buf, size_t len) {
//     inet_ntop(AF_INET, &(addr->sin_addr), buf, len);
// }

typedef struct {
    unsigned int userID;
    struct sockaddr_in addr; /* TFA client’s last known IP:port */
    int in_use;
} RegEntry;

static int find_entry(RegEntry *tab, int n, unsigned int userID) {
    for (int i = 0; i < n; ++i) {
        if (tab[i].in_use && tab[i].userID == userID) return i;
    }
    return -1;
}

static int upsert_entry(RegEntry *tab, int n, unsigned int userID, const struct sockaddr_in *addr) {
    int idx = find_entry(tab, n, userID);
    if (idx >= 0) {
        tab[idx].addr = *addr;
        return idx;
    }
    for (int i = 0; i < n; ++i) {
        if (!tab[i].in_use) {
            tab[i].in_use = 1;
            tab[i].userID = userID;
            tab[i].addr   = *addr;
            return i;
        }
    }
    return -1; /* table full */
}

int main(int argc, char *argv[]) {
    /* ---- CLI ---- */
    unsigned short tfaPort = TFA_DEFAULT_PORT;
    const char *pkeIP = PKE_DEFAULT_IP;
    unsigned short pkePort = PKE_DEFAULT_PORT;

    if (argc == 1) {
        /* use defaults */
    } else if (argc == 2) {
        tfaPort = (unsigned short)atoi(argv[1]);
    } else if (argc == 4) {
        tfaPort = (unsigned short)atoi(argv[1]);
        pkeIP   = argv[2];
        pkePort = (unsigned short)atoi(argv[3]);
    } else {
        fprintf(stderr, "Usage: %s [<TFA_PORT>]  or  %s <TFA_PORT> <PKE_IP> <PKE_PORT>\n",
                argv[0], argv[0]);
        exit(1);
    }

    /* ---- Socket + bind ---- */
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) DieWithError("socket() failed");

    struct sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port        = htons(tfaPort);

    if (bind(sock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0) {
        DieWithError("bind() failed");
    }

    set_recv_timeout(sock, RECV_TIMEOUT_MS);

    char selfIp[INET_ADDRSTRLEN] = TFA_DEFAULT_IP;
    printf("[TFA_SERVER] Listening on %s:%hu\n", selfIp, tfaPort);

    /* ---- PKE server address ---- */
    struct sockaddr_in pkeAddr;
    memset(&pkeAddr, 0, sizeof(pkeAddr));
    pkeAddr.sin_family = AF_INET;
    pkeAddr.sin_port   = htons(pkePort);
    if (inet_pton(AF_INET, pkeIP, &pkeAddr.sin_addr) != 1) {
        DieWithError("inet_pton(PKE_IP) failed");
    }
    char pkeIpStr[INET_ADDRSTRLEN];
    ip_to_str(&pkeAddr, pkeIpStr, sizeof(pkeIpStr));
    printf("[TFA_SERVER] Using PKE server %s:%hu\n", pkeIpStr, pkePort);

    /* ---- Registration table ---- */
    RegEntry regTable[MAX_CLIENTS];
    memset(regTable, 0, sizeof(regTable));

    /* ---- Main loop ---- */
    for (;;) {
        /* We expect most incoming packets to be TFAClientOrLodiServerToTFAServer. */
        TFAClientOrLodiServerToTFAServer in;
        memset(&in, 0, sizeof(in));
        struct sockaddr_in fromAddr;
        socklen_t fromLen = sizeof(fromAddr);

        ssize_t n = recvfrom(sock, &in, sizeof(in), 0, (struct sockaddr *)&fromAddr, &fromLen);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* idle timeout to keep server responsive */
                continue;
            }
            perror("[TFA_SERVER] recvfrom() failed");
            continue;
        }
        if ((size_t)n != sizeof(in)) {
            char ip[INET_ADDRSTRLEN]; ip_to_str(&fromAddr, ip, sizeof(ip));
            printf("[TFA_SERVER] Ignoring packet (size %zd != %zu) from %s:%hu\n",
                   n, sizeof(in), ip, ntohs(fromAddr.sin_port));
            continue;
        }

        char fromIp[INET_ADDRSTRLEN]; ip_to_str(&fromAddr, fromIp, sizeof(fromIp));

        switch (in.messageType) {
            case registerTFA: {
                /* Ask PKE for the user's public key */
                TOPKServer pkReq;
                memset(&pkReq, 0, sizeof(pkReq));
                pkReq.messageType = requestKey;
                pkReq.userID      = in.userID;
                pkReq.publicKey   = 0;

                if (sendto(sock, &pkReq, sizeof(pkReq), 0,
                           (struct sockaddr *)&pkeAddr, sizeof(pkeAddr)) != sizeof(pkReq)) {
                    perror("[TFA_SERVER] sendto(PKE requestKey) failed");
                    break; /* cannot proceed with registration */
                }

                FromPKServer pkResp;
                memset(&pkResp, 0, sizeof(pkResp));
                struct sockaddr_in pkFrom;
                socklen_t pkFromLen = sizeof(pkFrom);

                ssize_t rn = recvfrom(sock, &pkResp, sizeof(pkResp), 0,
                                      (struct sockaddr *)&pkFrom, &pkFromLen);
                if (rn < 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        printf("[TFA_SERVER] PKE lookup timeout for user=%u\n", in.userID);
                    } else {
                        perror("[TFA_SERVER] recvfrom(PKE response) failed");
                    }
                    break;
                }
                if ((size_t)rn != sizeof(pkResp)) {
                    printf("[TFA_SERVER] PKE response wrong size (%zd), ignoring\n", rn);
                    break;
                }
                /* Verify response is from the configured PKE */
                if (pkFrom.sin_addr.s_addr != pkeAddr.sin_addr.s_addr ||
                    pkFrom.sin_port        != pkeAddr.sin_port) {
                    char pkIp[INET_ADDRSTRLEN]; ip_to_str(&pkFrom, pkIp, sizeof(pkIp));
                    printf("[TFA_SERVER] Ignoring PKE response from unknown %s:%hu\n",
                           pkIp, ntohs(pkFrom.sin_port));
                    break;
                }
                if (pkResp.messageType != responsePublicKey) {
                    printf("[TFA_SERVER] Unexpected PKE messageType=%d (expected responsePublicKey)\n",
                           pkResp.messageType);
                    break;
                }
                if (pkResp.userID != in.userID) {
                    printf("[TFA_SERVER] PKE userID mismatch: got %u expected %u\n",
                           pkResp.userID, in.userID);
                    break;
                }
                if (pkResp.publicKey == 0) {
                    printf("[TFA_SERVER] No public key for user=%u; registration rejected\n", in.userID);
                    break;
                }

                /* Verify DS: rsaDecrypt(sig, pubKey) == timeStamp */
                unsigned long recovered = rsaDecrypt(in.digitalSig, pkResp.publicKey);
                if (recovered != in.timeStamp) {
                    printf("[TFA_SERVER] DS verify FAILED for user=%u (ts=%lu, rec=%lu) from %s:%hu\n",
                           in.userID, in.timeStamp, recovered, fromIp, ntohs(fromAddr.sin_port));
                    break;
                }

                /* Store/overwrite registration address */
                int idx = upsert_entry(regTable, MAX_CLIENTS, in.userID, &fromAddr);
                if (idx < 0) {
                    printf("[TFA_SERVER] Registration table FULL; user=%u not stored\n", in.userID);
                    break;
                }

                /* Send confirmTFA back to the TFA client */
                TFAServerToTFAClient confirm;
                memset(&confirm, 0, sizeof(confirm));
                confirm.messageType = confirmTFA;
                confirm.userID      = in.userID;

                if (sendto(sock, &confirm, sizeof(confirm), 0,
                           (struct sockaddr *)&fromAddr, sizeof(fromAddr)) != sizeof(confirm)) {
                    perror("[TFA_SERVER] sendto(confirmTFA) failed");
                    /* continue anyway */
                } else {
                    printf("[TFA_SERVER] confirmTFA -> user=%u to %s:%hu\n",
                           in.userID, fromIp, ntohs(fromAddr.sin_port));
                }

                /* We won’t block waiting for ackRegTFA; we’ll just log it when it arrives */
                break;
            }

            case ackRegTFA: {
                printf("[TFA_SERVER] ackRegTFA <- user=%u from %s:%hu\n",
                       in.userID, fromIp, ntohs(fromAddr.sin_port));
                break;
            }

            case requestAuth: {
                /* Called by Lodi Server */
                printf("[TFA_SERVER] requestAuth <- user=%u from %s:%hu\n",
                       in.userID, fromIp, ntohs(fromAddr.sin_port));

                int idx = find_entry(regTable, MAX_CLIENTS, in.userID);
                if (idx < 0) {
                    /* Not registered: no response (Lodi will timeout => failure) */
                    printf("[TFA_SERVER] user=%u not registered; no response to Lodi\n", in.userID);
                    break;
                }

                /* Push to the registered TFA client */
                TFAServerToTFAClient push;
                memset(&push, 0, sizeof(push));
                push.messageType = pushTFA;
                push.userID      = in.userID;

                struct sockaddr_in cliAddr = regTable[idx].addr;
                char cliIp[INET_ADDRSTRLEN]; ip_to_str(&cliAddr, cliIp, sizeof(cliIp));

                if (sendto(sock, &push, sizeof(push), 0,
                           (struct sockaddr *)&cliAddr, sizeof(cliAddr)) != sizeof(push)) {
                    perror("[TFA_SERVER] sendto(pushTFA) failed");
                    /* treat as failure: no response to Lodi */
                    break;
                }
                printf("[TFA_SERVER] pushTFA -> user=%u to %s:%hu\n",
                       in.userID, cliIp, ntohs(cliAddr.sin_port));

                /* Wait for ackPushTFA from that client */
                bool ok = false;
                for (int tries = 0; tries <= ACK_RETRIES; ++tries) {
                    TFAClientOrLodiServerToTFAServer ack;
                    memset(&ack, 0, sizeof(ack));
                    struct sockaddr_in ackFrom;
                    socklen_t ackLen = sizeof(ackFrom);

                    ssize_t rn = recvfrom(sock, &ack, sizeof(ack), 0,
                                          (struct sockaddr *)&ackFrom, &ackLen);
                    if (rn < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            if (tries < ACK_RETRIES) {
                                printf("[TFA_SERVER] waiting for ackPushTFA (retry %d/%d)\n",
                                       tries + 1, ACK_RETRIES);
                                continue;
                            } else {
                                printf("[TFA_SERVER] ackPushTFA timeout for user=%u\n", in.userID);
                                break;
                            }
                        } else {
                            perror("[TFA_SERVER] recvfrom(ackPushTFA) failed");
                            break;
                        }
                    } else if ((size_t)rn != sizeof(ack)) {
                        printf("[TFA_SERVER] ignoring packet of unexpected size: %zd\n", rn);
                        continue;
                    } else if (ack.messageType == ackPushTFA &&
                               ack.userID == in.userID &&
                               ackFrom.sin_addr.s_addr == cliAddr.sin_addr.s_addr &&
                               ackFrom.sin_port        == cliAddr.sin_port) {
                        printf("[TFA_SERVER] ackPushTFA <- user=%u from %s:%hu\n",
                               in.userID, cliIp, ntohs(cliAddr.sin_port));
                        ok = true;
                        break;
                    } else {
                        /* Could be other traffic (e.g., another register); log and keep waiting */
                        char otherIp[INET_ADDRSTRLEN]; ip_to_str(&ackFrom, otherIp, sizeof(otherIp));
                        printf("[TFA_SERVER] received different msgType=%d from %s:%hu (ignored while waiting)\n",
                               ack.messageType, otherIp, ntohs(ackFrom.sin_port));
                        continue;
                    }
                }

                if (!ok) {
                    /* Failure policy: no response to Lodi; it will timeout and deny */
                    break;
                }

                /* Success: send responseAuth back to Lodi (the original sender of requestAuth) */
                TFAServerToLodiServer out;
                memset(&out, 0, sizeof(out));
                out.messageType = responseAuth;
                out.userID      = in.userID;

                if (sendto(sock, &out, sizeof(out), 0,
                           (struct sockaddr *)&fromAddr, sizeof(fromAddr)) != sizeof(out)) {
                    perror("[TFA_SERVER] sendto(responseAuth) failed");
                } else {
                    printf("[TFA_SERVER] responseAuth -> user=%u to %s:%hu\n",
                           in.userID, fromIp, ntohs(fromAddr.sin_port));
                }
                break;
            }

            case ackPushTFA: {
                /* Late/out-of-context ack; log it. */
                printf("[TFA_SERVER] ackPushTFA (unsolicited) <- user=%u from %s:%hu\n",
                       in.userID, fromIp, ntohs(fromAddr.sin_port));
                break;
            }

            default: {
                printf("[TFA_SERVER] Unknown messageType=%d from %s:%hu (ignored)\n",
                       in.messageType, fromIp, ntohs(fromAddr.sin_port));
                break;
            }
        }
    }

    /* not reached */
    close(sock);
    return 0;
}
