#include <stdio.h>
#include "rsa.h"

int main(void) {
    unsigned long e = computePrivateKey(phiN);       // private exponent
    printf("compute public key \n");
    unsigned long d = computePublicKey(e, phiN);     // public exponent
    printf("keys computed \n");

    unsigned long msg = 1761921299;

    unsigned long sig = rsaEncrypt(msg, e);  // sign/encrypt
    unsigned long check = rsaDecrypt(sig, d);        // verify/decrypt

    printf("p=%u q=%u n=%lu phiN=%lu\n", p, q, n, phiN);
    printf("privateKey(e)=%lu publicKey(d)=%lu\n", e, d);
    printf("msg=%lu sig=%lu check=%lu\n",
            msg, sig, check);
    printf("Match: %s\n", (msg == check ? "YES" : "NO"));
}