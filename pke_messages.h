/*pke_messages.h*/
#ifndef PKEMESSAGES_H
#define PKEMESSAGES_H

#define PKE_DEFAULT_IP "34.56.167.165"
#define PKE_DEFAULT_PORT 27747

//Message  to PKE server (renamed PClientToPkServer)
typedef struct {
    enum {registerKey, requestKey} messageType;
    unsigned int userID;
    unsigned int publicKey; //contains 0 if type is request_key
} TOPKServer;
/*a. messageType = registerKey:
o The userID field should contain the user's own identifier when registering.
o The publicKey field should contain the user's own public key.
b. messageType = requestKey:
o The userID field should contain the identifier of the user whose public key it is requesting.
o The publicKey field should be 0.*/

//Message from PKEserver (renamed PKServerTOPClientOrLodiServer)
typedef struct {
    enum {ackRegistrerKey, responsePublicKey} messageType;
    unsigned int userID;
    unsigned int publicKey;
} FromPKServer;
/*a. messageType = ackRegisterKey:
o Response to client's messageType = registerKey
o The userID field should contain the registering user's identifier.
o The publicKey field should contain the user's public key.
b. messageType = responsePublicKey:
o Response to client's messageType = requestKey
o The userID field should contain the user identifier of requested public key
o The publicKey field should contain the requested user's public key.*/

#endif