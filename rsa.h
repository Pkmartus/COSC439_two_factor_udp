/*rsa.h*/
#ifndef RSA_H
#define RSA_H

//come up with 2 large primes p and q
const unsigned long p = 83639;
const unsigned long q = 92737;
//compute n from p and q
const unsigned long n = p*q;
//Phi(n)
const unsigned long phiN = (p-1)*(q-1);

//modular multiplacation to prevent overflow
unsigned long modularMultiplacation(unsigned long a, unsigned long b, unsigned long mod) {
    unsigned long result = 0;
    a = a % mod; //reduce a

    while (b > 0) {
        if (b & 1) 
            result = (result + a) % mod; //if bit is set add a to result and reduce by mod
        a = (a * 2) % mod; //double a and reduce by mod
        b >>= 1; //shift the bits
    }
    return result;
}

unsigned long powerMod(unsigned long base, unsigned long exp) {
    unsigned long result = 1;
    base = base % n; //reduce the base by n

    while (exp > 0) {
        if (exp & 1)
            result = modularMultiplacation(result, base, n);  //use modular multiplacation to safely multiply and reduce
        base = modularMultiplacation(base, base, n); //square base and reduce
        exp >>= 1; //shift bits
    }

    return result;
}

unsigned long rsaEncrypt(unsigned long encryption_input, unsigned long privateKey) 
{
    return powerMod(encryption_input, privateKey);
}

unsigned long rsaDecrypt(unsigned long decryption_input, unsigned long publicKey)
{
    return powerMod(decryption_input, publicKey);
}

unsigned long computePrivateKey(unsigned long phiN)
{
    //find the largest number that is pairwise prime with phi n
      // Fallback: search upwards
    for (unsigned long e = 3; e < phiN; e += 2) {
        unsigned long a = e, b = phiN;
        while (b != 0) {
            unsigned long t = b;
            b = a % b;
            a = t;
        }
        if (a == 1) return e;
    }
    return 0;
}

unsigned long computePublicKey(unsigned long privateKey, unsigned long phiN)
{
    //return modinv(A, M);
    unsigned long mod = phiN;
    long y = 0, x = 1;
    unsigned long qoutent, temp;

    if (phiN == 1)
         return 0;

    while (privateKey > 1) {
         // q is quotient
         qoutent = privateKey / phiN;
         temp = phiN;

        // phiN is remainder now, process same as
        // Euclid's algo
        phiN = privateKey % phiN;
        privateKey = temp;
        temp = y;

         // Update y and x
         y = x - qoutent * y;
         x = temp;
     }

     // Make x positive
     if (x < 0)
         x += mod;

     return x;
}

#endif