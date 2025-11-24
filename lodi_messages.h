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
    enum {ackLogin, ackPost, ackFeed, ackFollow, ackUnfollow, ackLogout, feedMessage} messageType;
    unsigned int userID; /* unique client identifier */
    char message[100]; /* posted text message */
    unsigned int next; //my addition, used in ackFeed to send the number of messages coming in the feed. send type feed message after that
} LodiServerMessage; /* an unsigned int is 32 bits = 4 bytes */



#endif