# COSC439_two_factor_udp
Project for COSC439: Computing Network Principles.

Files we worked on by both devs, but the primary devision of work was
    Patrick Martus:
        lodi_client.c
        lodi_server.c
        rsa.h
    Chanuth Jayatissa
        tfa_client.c
        tfa_server.c
        pke_server.c
    Other header files contain the structures from documention

-Structures defined by documentation are contained in header files so that multiple files have access to one definition.
-Changed name of structures for pke server from the documentation as more files use them than the ones described by the previous names
-Usage descriptions from documentation are also in header files for structs

Usage:
    -If needed change addresses or ports in the header files for each server, they will be changed in all nessesary references
    -Build files: make
    -No arguments are needed for any files
    -Start server files (in any order) with:    ./lodi_server 
                                                ./tfa_server 
                                                ./pke_server
    -Start lodi_client: ./lodi_client
    -Enter integer user ID
    -Start tfa_client: ./tfa_client
    -Enter the same user ID
    -Return to lodi_client and press enter to continue login process
    -0 will exit lodi_client after login process
    -all other files can be closed with a standard ctrl+c

Other notes:
-I couldn't get the rsa encryption working within the size limits of unsigned int or long, so the timestamp is reduced in size %n before it is encrypted
