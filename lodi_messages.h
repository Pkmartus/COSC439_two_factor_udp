/*lodi_messages.h*/
#ifndef LODIMESSAGES_H
#define LODIMESSAGES_H

#define LODI_DEFAULT_IP "34.69.20.99"
#define LODI_DEFAULT_PORT 8080

/*sample code from handout*/

//message from Lodi Client to Lodi Server
typedef struct {
    enum {login, post, feed, follow, unfollow, logout } messageType;
    unsigned int userID; /* user identifier */
    unsigned int recipientID; /* message recipient identifier */
    unsigned long timestamp; /* timestamp */
    unsigned long digitalSig; /* encrypted timestamp */
    char message[120]; /* text message */
} PClientToLodiServer;


//message from Lodi server to lodi client
typedef struct {
    enum {ackLogin, ackPost, ackFeed, ackFollow, ackUnfollow, ackLogout, feedMessage} messageType;
    unsigned int userID; /* unique client identifier */
    char message[120]; /* posted text message */
    unsigned int next; //my addition, used in ackFeed to send the number of messages coming in the feed. send type feed message after that
} LodiServerMessage; /* an unsigned int is 32 bits = 4 bytes */

//structure for keeping track of known users and users that are logged in or not
typedef struct {
    unsigned int userID;
    unsigned int signedIn; //0 if logged out, 1 if signed in
    unsigned int numIdols; //number of users followed by user
    unsigned int folllowedIdolIDs[20]; //userID's of idols followed by user
} UserSignInStatus;

//structure for storing user messages
typedef struct {
    unsigned int userID;
    char message[100];
} UserMessages;


#endif