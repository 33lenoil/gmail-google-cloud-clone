#include <stdio.h>
#include <stdlib.h>

#include "http-request.h"
#include <string.h>
#include <unistd.h>
using namespace std;

HttpRequest::HttpRequest(int fd, bool vflag, bool& connection_alive){
    this->valid = true;
    this->socket_fd = fd;
    char buf[BUFSIZE];
    memset(buf, 0, BUFSIZE);
    bool initial = true;
    bool content = false;
    int contentLen = 0;
    int recvd = 0;
    while(true) {
        int n = read(fd, buf+recvd, BUFSIZE-recvd);
        if(n <= 0){
            if(n < 0 && vflag) fprintf(stderr, "[%d] Server failed to read from connection: %s\n", fd, strerror(errno));
            this->uri = "";
            this->headers["Connection"] = "close";
            connection_alive = false;
            return;
        }
        fprintf(stderr, "n: %d\n", n);
        fprintf(stderr, "buf: %s\n", buf);
        fprintf(stderr, "------\n");
        recvd += n;
        char command[BUFSIZE];
        char *CRLF = strstr(buf, "\r\n");
        while(CRLF){
            recvd -= (CRLF-buf);
            strncpy(command, buf, CRLF-buf);
            command[CRLF-buf] = '\0';
            // process the line
            if(initial){
                // extract method
                char *token = strtok(command, " ");
                if(token == NULL) {
                    this->valid = false;
                    return;
                }
                string method_str(token);
                this->method = method_str;
                // extract uri
                token = strtok(NULL, " ");
                if(token == NULL) {
                    this->valid = false;
                    return;
                }
                string uri_str(token);
                this->uri = uri_str;
                // extract http version
                token = strtok(NULL, " ");
                if(token == NULL) {
                    this->valid = false;
                    return;
                }
                string version_str(token);
                this->version = version_str;
                // set initial flag to be false
                initial = false;
            } else {
                if(content){
                    fprintf(stderr, "buf line 67: %s\n", buf);
                }
                if(strlen(command) != 0) {
                    // extract header item title
                    char *token = strtok(command, ": ");
                    if(token == NULL) {
                        this->valid = false;
                        fprintf(stderr, "line 71\n");
                        return;
                    }
                    string title(token);
                    // extract header item value
                    token = strtok(NULL, "");
                    if(token == NULL) {
                        this->valid = false;
                        fprintf(stderr, "line 79\n");
                        return;
                    }
                    string value(token);
                    // close connection when receive "Connection: close" from client
                    if(title == "Connection" && value == "close"){
                        connection_alive = false;
                    }
                    this->headers[title] = value;
                }else{
                    // arrive at the CSRF before content
                    if(this->headers.find("Content-Length") != this->headers.end()){
                        contentLen = stoi(this->headers["Content-Length"]);
                        content = true;
                    }
                }
                
            }
            // remove the processed command from buffer
            recvd -= strlen("\r\n");
            CRLF += strlen("\r\n");
            if(recvd > 0) {
                char temp[BUFSIZE];
                memset(temp, 0, BUFSIZE);
                memcpy(temp, CRLF, strlen(CRLF));
                memset(buf, 0, BUFSIZE);
                memcpy(buf, temp, strlen(temp));
                if(content){
                    string content_str(buf);
                    fprintf(stderr, "content: %s\n", buf);
                    fprintf(stderr, "content_str length: %ld\n", content_str.length());
                    this->content = content_str; 
                    return;   
                }
                //fprintf(stderr, "Reamaining: \n%s\n", buf);
            } else {
                memset(buf, 0, BUFSIZE);
                fprintf(stderr, "line 116\n");
                return;
            }
            CRLF = strstr(buf, "\r\n");
        }
        fprintf(stderr, "line 121\n");
    }
}

void HttpRequest::print() {
    fprintf(stderr, "\tMethod: %s\n", method.c_str());
    fprintf(stderr, "\tURI: %s\n", uri.c_str());
    fprintf(stderr, "\tVersion: %s\n", version.c_str());

    fprintf(stderr, "\tHeaders:\n");
    for (const auto& header : headers) {
        fprintf(stderr, "\t  %s: %s\n", header.first.c_str(), header.second.c_str());
    }

    fprintf(stderr, "\tContent: %s\n", content.c_str());
    fprintf(stderr, "\tValid: %s\n", (valid ? "true" : "false"));
    return;
}