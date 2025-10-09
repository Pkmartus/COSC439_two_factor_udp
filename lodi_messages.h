/*lodi_messages.h*/
/*includes things that   */
#ifndef LODIMESSAGES_H
#define LODIMESSAGES_H

/*sample code from handout*/
typedef struct {
    enum {ackLogin} messageType;
    unsigned int userID;
} LodiServerToLodiClientAcks;

typedef struct {
    enum{ackRegisterKey, responsePublicKey} messageType;
    unsigned int userID; 
    unsigned int publicKey;
} PKServerToLodiCLient;

typedef struct {
    enum {registerKey, requestKey} messageType;
    unsigned int userID;
    unsigned int publicKey; //contains 0 if type is request_key
} PClientTOPKServer;

typedef struct {
    enum {ackRegistrerKey, responsePublicKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} PKServerTOPClientOrLodiServer;



#endif