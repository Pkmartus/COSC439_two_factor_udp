/*tfa_messages.h*/
#ifndef TFAMESSAGES_H /* include guard prevents header being added to a file more than once*/
#define TFAMESSAGES_H

/* sample code from handout */
typedef struct {
    enum {registerTFA, ackRegTFA, ackPushTFA, requestAuth} messageType;
                        
    unsigned int userID; /*always used*/
    unsigned long timeStamp; /*timestamp during registration, otherwise 0*/
    unsigned long digitalSig; /*encrypted timestamp during registration, otherwise 0*/
} TFAClientOrLodiServerToTFAServer;

typedef struct {
    enum {confirmTFA, pushTFA} messageType;
    unsigned int userID; //contains user identifier
} TFAServerToTFAClient;

typedef struct {
    enum {responseAuth} messageType;
    unsigned int userID;
} TFAServerToLodiServer;

#endif