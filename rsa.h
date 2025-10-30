/*rsa.h*/
#ifndef RSA_H
#define RSA_H

//come up with 2 large primes p and q
const unsigned int p = 7;
const unsigned int q = 11;
//compute n from p and q
const unsigned int n = p*q;
//Phi(n)
const unsigned int phiN = (p-1)*(q-1);

//method declarations
long powerMod(long base, unsigned int exp);
long recPowerMod(long base, unsigned int exp);
long power(unsigned int base, unsigned int e);
long rsaEncrypt(long encryption_input, unsigned int privateKey);
long rsaDecrypt(long decryption_input, unsigned int publicKey);
unsigned long computePrivateKey(unsigned long phiN);
unsigned long computePublicKey(long privateKey, long phiN);

long rsaEncrypt(long encryption_input, unsigned int privateKey) 
{
    return powerMod(encryption_input, privateKey);
}

long powerMod(long base, unsigned int exp)
{
    long result = 1;

    //check each bit in power, if set run function on one bit smaller, square the result and mod n
    for(int i = 31; i > 0; i--)
    {

        if(exp&(1<<i)) {
            //for each set bit seperate it into smaller bits
            unsigned int next = recPowerMod(base, power(2, (i))/2); //convert bit into it's value
            result = result * ((next*next)%n) %n; //a^e mod b = is the same as ((a^(e/2) mod b)*(a^(e/2) mod b)) mod b
        }
    }
    return (result*(base%n))%n;
}

//method to avoid integer overflow using algorithm discussed in class
long recPowerMod(long base, unsigned int exp) {

    if (exp == 1)
        return base%n; //base case when we've gotten down to a mod b
    else {
        unsigned int next = recPowerMod(base, exp/2); //otherwise split it again
        return (next*next)%n;
    }
}


//simple method to raise a number to a power 
long power(unsigned int base, unsigned int e)
{
    //any number raised to 0 is 1
    if(e == 0)
        return 1;
    unsigned int result = base;
    for(int i = e-1; i > 0; i--)
    {
        result = result*base;
    }
    return result;
}

long rsaDecrypt(long decryption_input, unsigned int publicKey)
{
    return powerMod(decryption_input, publicKey);
}

unsigned long computePrivateKey(unsigned long phiN)
{
    //find the largest number that is pairwise prime with phi n
    int prime=0;
    for(long i = phiN-1; i > 1; i--)
    {
        for(long j = i; j > 1; j--)
        {
            if (i % j == 0 && phiN % j == 0)
            {
                prime = 0;
                break;
            }
            prime=1;
        }
        if(prime > 0)
            return i;
    }
    return 0;
}


//find the public key based on: d*e = 1 mod Phi n
unsigned long computePublicKey(long privateKey, long phiN)
{
    for(int i = 2; i < phiN; i++)
    {
        if((privateKey * i % phiN == 1))
            return i;
    }
    return -1;
}



#endif