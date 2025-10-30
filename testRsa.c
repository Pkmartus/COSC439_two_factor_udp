#include <stdio.h>
#include "rsa.h"


int main() 
{
    printf("EXPECTED: %d\n", power(105, 53)%77);
    printf("the encrypted number is %d\n", rsaEncrypt(105, 53));
}