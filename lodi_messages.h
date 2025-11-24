/*lodi_messages.h*/
#ifndef LODIMESSAGES_H
#define LODIMESSAGES_H

#define LODI_DEFAULT_IP "127.0.0.1"
#define LODI_DEFAULT_PORT 27745

/*sample code from handout*/

//message from Lodi Client to Lodi Server
typedef struct {
    enum {login, post, feed, follow, unfollow, logout } messageType;
    unsigned int userID; /* user identifier */
    unsigned int recipientID; /* message recipient identifier */
    unsigned long timestamp; /* timestamp */
    unsigned long digitalSig; /* encrypted timestamp */
    char message[100]; /* text message */
} PClientToLodiServer;


//message from Lodi server to lodi client
typedef struct {
    enum {ackLogin, ackPost, ackFeed, ackFollow, ackUnfollow, ackLogout } messageType;
    unsigned int userID; /* unique client identifier */
    char message[100]; /* posted text message */
    unsigned int next; //my addition for determining how many messages in feed contains the number of messages after the current one, contains 0 if last message, contains 0 if any other type than ackFeed
    //may need to break out into it's own message type if determining size in advance becomes an issue
} LodiServerMessage; /* an unsigned int is 32 bits = 4 bytes */



#endif