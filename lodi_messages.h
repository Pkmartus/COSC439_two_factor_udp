/*lodi_messages.h*/
#ifndef LODIMESSAGES_H
#define LODIMESSAGES_H

#define LODI_DEFAULT_IP "127.0.0.1"
#define LODI_DEFAULT_PORT 27745

/*sample code from handout*/

//message from Lodi Client to Lodi Server
typedef struct {
    enum {login} messageType;
    unsigned int userID; //user identifier
    unsigned int recipientID; //message recipient identifier
    unsigned long timestamp; //timestamp
    unsigned long digitalSig; //encrypted timestamp
} PClientToLodiServer;


//message from Lodi server to lodi client
typedef struct {
    enum {ackLogin} messageType;
    unsigned int userID;
} LodiServerToLodiClientAcks;
/*a. messageType = ackLogin:
o Response to Lodi client's messageType = login
o The userID field should contain the registering user's identifier*/

#endif