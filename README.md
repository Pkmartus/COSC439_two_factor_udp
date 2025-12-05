# COSC439_two_factor_udp
Project for COSC439: Computing Network Principles.

-Edited the LodiServerMessages struct a bit to account for the feed
    -Added a feedMessage type and an additional int attribute: next
    -AckFeed doesn't send any of the messages, instead it sends the number of messages to come as "next"
    -FeedMessage contains the actual message and the client knows how many to expect because of the ack
-Also change both structs to increase the message size to 120 allowing the server to store a 100 character message but still send a little extra back
    -This allows us to send the id of the idol who posted the message and a few other cases

Usage:
    -If running locally or on emunix no changes to ip or ports is needed
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
    -Return to lodi_client and press 1 to login
    -0 will exit lodi_client after login process
    -all other files can be closed with a standard ctrl+c

Other notes:
-Tested on gcp, was able to communicate from other gcp instances as well as a local instance on my machine
