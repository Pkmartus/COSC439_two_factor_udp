/*tfa_messages.h*/
#ifndef TFAMESSAGES_H /* include guard prevents header being added to a file more than once*/
#define TFAMESSAGES_H

#define TFA_DEFAULT_IP "35.238.71.225"
#define TFA_DEFAULT_PORT 27746

/* sample code from handout */
typedef struct {
    enum {registerTFA, ackRegTFA, ackPushTFA, requestAuth} messageType;
                        
    unsigned int userID; 
    unsigned long timeStamp; 
    unsigned long digitalSig; 
} TFAClientOrLodiServerToTFAServer;
/*messageType = registerTFA :
o Message sent from TFA Client to the TFA server
o The userID field should contain the user's own identifier when registering.
o The timestamp field should contain current time
o The digitalSig field should contain encrypted timestamp
b. messageType = ackRegTFA :
o Message sent from TFA Client to the TFA server
o The userID field should contain the user's own identifier.
o The timestamp field should contain 0
o The digitalSig field should contain 0
c. messageType = ackPushTFA :
o Message sent from TFA Client to the TFA server
o The userID field should contain the user's own identifier.
o The timestamp field should contain 0
o The digitalSig field should contain 0
d. messageType = requestAuth:
o Message sent from Lodi server to the TFA server
o The userID field should contain the user identifier during login.
o The timestamp field should contain 0
o The digitalSig field should contain 0*/

typedef struct {
    enum {confirmTFA, pushTFA} messageType;
    unsigned int userID; 
} TFAServerToTFAClient;
/*a. messageType = confirmTFA
o Response to client's messageType = registerTFA
o The userID field should contain the registering user's identifier.
b. messageType = pushTFA
o Response to Lodi server's requestAuth message
o The userID field should contain the user identifier*/

typedef struct {
    enum {responseAuth} messageType;
    unsigned int userID;
} TFAServerToLodiServer;
/*a. messageType = responseAuth:
o Message sent from TFA server to the Lodi server
o The userID field should contain the user identifier during login*/

#endif