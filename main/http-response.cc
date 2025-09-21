#include <stdio.h>
#include <stdlib.h>
#include "http-response.h"
#include "utils.h"
#include <string.h>
#include <cstring>
#include <algorithm>

using namespace std;

unordered_map<int, string> code_map = {
    // Successful
    {200, "OK"},
    {201, "Created"},
    // Redirections
    {301, "Moved Permanently"},
    {302, "Found"},
    {307, "Temporary Redirect"},
    // Client Error
    {400, "Bad Request"},
    {401, "Unauthorized"},
    {403, "Forbidden"},
    {404, "Not Found"},
    {405, "Method Not Allowed"},
    // Server Error
    {500, "Internal Server Error"},
    {501, "Not Implemented"},
    {502, "Bad Gateway"},
    {503, "Service Unavailable"}
};

HttpResponse::HttpResponse(HttpRequest req) {
    this->version = req.version;
    this->socket_fd = req.socket_fd;
    this->headers[CONTENT_LEN] = to_string(0);
    this->headers[CONNECTION] = req.headers[CONNECTION];
    this->valid = true;
}

void HttpResponse::setStatus(int status_code) {
    if(code_map.find(status_code) != code_map.end()){
        this->status_code = status_code;
        this->status_msg = code_map[status_code];
    }else{
        this->valid = false;
    }
}

void HttpResponse::setMsg(string msg) {
    this->status_msg = msg;
}

void HttpResponse::setHeader(string title, string value){
    this->headers[title] = value;
}

void HttpResponse::setBody(string body){
    this->body = body;
}

void HttpResponse::send() {
    
    size_t bufSize = BUFSIZE;
    char *resBuf = new char[bufSize];
    size_t offset = 0;
    offset += sprintf(resBuf + offset, "%s %d %s\r\n", this->version.c_str(), this->status_code, this->status_msg.c_str());
    offset += sprintf(resBuf + offset, "Date: %s\r\n", getGMT().c_str());
    if(this->status_code == 302 || this->status_code == 307){
        offset += sprintf(resBuf + offset, "%s: %s\r\n", "Location", this->headers["Location"].c_str());
        
    } 

    offset += sprintf(resBuf + offset, "%s: %s\r\n", CONTENT_TYPE.c_str(), this->headers[CONTENT_TYPE].c_str());
    offset += sprintf(resBuf + offset, "%s: %s\r\n", CONTENT_LEN.c_str(), this->headers[CONTENT_LEN].c_str());
    offset += sprintf(resBuf + offset, "%s: %s\r\n", CONNECTION.c_str(), this->headers[CONNECTION].c_str());
    if((this->headers).find(ACCESS_CONTROL_ALLOW_ORIGIN) != (this->headers).end()){
        string ip = this->headers[ACCESS_CONTROL_ALLOW_ORIGIN];
        offset += sprintf(resBuf + offset, "%s: %s\r\n", ACCESS_CONTROL_ALLOW_ORIGIN.c_str(), ip.c_str());
        
    }
    if((this->headers).find(SET_COOKIE) != (this->headers).end()){
        string sid, username;
        string cookie = this->headers[SET_COOKIE];
        size_t semicolon = cookie.find(';');
        sid = cookie.substr(0, semicolon);
        username = cookie.substr(semicolon+1);
        offset += sprintf(resBuf + offset, "%s: %s\r\n", SET_COOKIE.c_str(), sid.c_str());
        offset += sprintf(resBuf + offset, "%s: %s\r\n", SET_COOKIE.c_str(), username.c_str());
    }
    offset += sprintf(resBuf + offset, "\r\n");
    if(this->headers[CONTENT_LEN]!= "0") {
        size_t bodyLen = this->body.length();

        if(offset + bodyLen >= bufSize-1){
            bufSize = offset + bodyLen + 1;
            char *newResBuf = new char[bufSize];
            memcpy(newResBuf, resBuf, offset);
            delete[] resBuf;
            resBuf = newResBuf;
        }

        offset += sprintf(resBuf + offset, "%s\n", this->body.c_str());
    }
    resBuf[offset] = '\0';
    fprintf(stderr, "[%d] Sending response back\n%s\n", this->socket_fd, resBuf);

    do_write(this->socket_fd, resBuf, offset);
    delete[] resBuf;
} 