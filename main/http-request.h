#ifndef HTTP_REQUEST_H
#define HTTP_REQUEST_H

#include <string>
#include <unordered_map>
using namespace std;

#define BUFSIZE 20480

class HttpRequest {
    public:
        string method;
        string uri;
        string version;
        unordered_map<string, string> headers;
        string content;
        bool valid;
        int socket_fd;
        string sid; // should ONLY be used by /login handler
        string username; // should ONLY be used by /login handler
        
        // constructor
        HttpRequest(int fd, bool vflag, bool& connection_alive);
        // debug printing
        void print();
};

#endif /* HTTP_REQUEST_H */