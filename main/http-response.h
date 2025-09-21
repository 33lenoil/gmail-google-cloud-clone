#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include <string>
#include <unordered_map>
#include "http-request.h"
using namespace std;

#define BUFSIZE 20480

const static string CONTENT_TYPE = "Content-Type";
const static string CONTENT_LEN = "Content-Length";
const static string CONNECTION = "Connection";
const static string SET_COOKIE = "Set-Cookie";
const static string ACCESS_CONTROL_ALLOW_ORIGIN = "Access-Control-Allow-Origin";
// Referencee: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status#client_error_responses
extern unordered_map<int, string> code_map; 

class HttpResponse {
    public:
        string version;
        int status_code;
        string status_msg;
        // Content-Encoding, Content-Type, Date
        unordered_map<string, string> headers;
        string body;
        bool valid;
        int socket_fd;
        // constructor
        HttpResponse(HttpRequest req);
        // setters
        void setStatus(int status_code);
        void setMsg(string msg);
        void setHeader(string title, string value);
        void setBody(string body);

        // generator
        void send();
        // debug printing
        void print();
};

#endif /* HTTP_RESPONSE_H */