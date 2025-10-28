/*rsa.h*/
#ifndef RSA_H
#define RSA_H

long rsa_encrypt(long encryption_input, unsigned int privateKey) 
{
    return encryption_input*privateKey;
}

long rsa_decrypt(long decryption_input, unsigned int publicKey)
{
    return decryption_input/publicKey;
}

unsigned long computePrivateKey(unsigned long phiN)
{
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