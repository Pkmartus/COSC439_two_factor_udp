#include <stdio.h>  /* for perror() */
#include <stdlib.h> /* for exit() */

//taken from sample code

void DieWithError(char *errorMessage)
{
	perror(errorMessage);
	exit(1);
}