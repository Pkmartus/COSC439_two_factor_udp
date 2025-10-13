/*lodi_messages.h*/
/*includes things that   */
#ifndef LODIMESSAGES_H
#define LODIMESSAGES_H

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

//message from PKE server to PKE client
typedef struct {
    enum{ackRegisterKey, responsePublicKey} messageType;
    unsigned int userID; 
    unsigned int publicKey;
} PKServerToLodiCLient;

//Message from Lodi client to PKE server
typedef struct {
    enum {registerKey, requestKey} messageType;
    unsigned int userID;
    unsigned int publicKey; //contains 0 if type is request_key
} PClientTOPKServer;

//Message from PKEserver to Lodi Client or LodiServer
typedef struct {
    enum {ackRegistrerKey, responsePublicKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} PKServerTOPClientOrLodiServer;



#endif