#include "utils.h"
#include "email_utils.h"
#include "request-handler.h"
#include "backendMessage.h"
#include <sstream>
#include <arpa/inet.h>
#include <vector>
#include "smtpserver.h"
#include "smtpclient.h"

using namespace std;

struct uidl_return
{
    std::string hash_id;
    std::string subject;
    std::string sender;
    std::string date;
};

sockaddr_in RequestHandler::backendCoordinatorAddr;
sockaddr_in RequestHandler::backendWorkerAddr;

int initBackendCoord()
{
    int sockfd = socket(PF_INET, SOCK_STREAM, 0);

    bzero(&RequestHandler::backendCoordinatorAddr, sizeof(RequestHandler::backendCoordinatorAddr));
    RequestHandler::backendCoordinatorAddr.sin_family = AF_INET;
    RequestHandler::backendCoordinatorAddr.sin_port = htons(10000);
    inet_pton(AF_INET, "127.0.0.1", &(RequestHandler::backendCoordinatorAddr.sin_addr));

    connect(sockfd, (struct sockaddr *)&RequestHandler::backendCoordinatorAddr, sizeof(RequestHandler::backendCoordinatorAddr));
    return sockfd;
}

int initBackendWorker(string ipPort)
{
    int sockfd = socket(PF_INET, SOCK_STREAM, 0);

    bzero(&RequestHandler::backendWorkerAddr, sizeof(RequestHandler::backendWorkerAddr));
    RequestHandler::backendWorkerAddr.sin_family = AF_INET;
    RequestHandler::backendWorkerAddr.sin_port = htons(
        stoi(ipPort.substr(ipPort.find(":") + 1)));
    inet_pton(AF_INET, "127.0.0.1", &(RequestHandler::backendWorkerAddr.sin_addr));

    connect(sockfd, (struct sockaddr *)&RequestHandler::backendWorkerAddr, sizeof(RequestHandler::backendWorkerAddr));
    return sockfd;
}

void addFakeAccount(string username, string password)
{
    backendMessage putMsg = backendMessage(backendMessage::Req, "1", 1);
    putMsg.setReqMsg(backendMessage::requestType::PUT, USER_TABLE, username, "pwd", "", password);

    vector<char> buffer;
    char *inBuf = (char *)malloc(4096);

    putMsg.serialize(buffer);

    // set up socket & connect to backend Coordinator
    int coordfd = initBackendCoord();
    // send msg to Coordinator to get worker redirection
    int writeBytes = write(coordfd, buffer.data(), buffer.size());
    // read redirection instruction from Coordinator
    int readBytes = read(coordfd, inBuf, 4096);
    // parse delegated Worker IP
    backendMessage putMsgRep = backendMessage();
    putMsgRep.deserialize(inBuf, readBytes);
    string ipPort = putMsgRep.getRedirMsg().ipPort;
    // fprintf(stderr, "Redirected to worker ip: %s\n", ipPort.c_str());
    // close Coordinator socket
    close(coordfd);
    free(inBuf);
    // set up worker socket
    int workerfd = initBackendWorker(ipPort);
    // send PUT request msg to Worker
    writeBytes = write(workerfd, buffer.data(), buffer.size());
    // read response from Worker
    char *newInBuf = (char *)malloc(4096);
    readBytes = read(workerfd, newInBuf, 4096);
    // parse response from Worker
    backendMessage putMsgRep2 = backendMessage();
    putMsgRep2.deserialize(newInBuf, readBytes);
    // close Worker socket
    close(workerfd);
    free(newInBuf);
}

bool isCookieValid(HttpRequest &req)
{
    if (req.headers.find("Cookie") == req.headers.end())
        return false;
    string cookie = req.headers["Cookie"];
    size_t startPos = cookie.find("sid=");
    size_t endPos = cookie.find(";", startPos);
    string sid = cookie.substr(startPos + 4, endPos - (startPos + 4));
    fprintf(stderr, "Request contains sid: %s\n", sid.c_str());
    fprintf(stderr, "Session recorded sid: %s\n", req.sid.c_str());
    startPos = cookie.find("username=");
    string username = cookie.substr(startPos + 9);
    fprintf(stderr, "Request contains username: %s\n", username.c_str());
    fprintf(stderr, "Session recorded username: %s\n", req.username.c_str());
    
    fprintf(stderr, "sid != req.sid : %d\n", sid != req.sid );
    fprintf(stderr, "username != req.username: %d\n", username != req.username);

    if (sid != req.sid || username != req.username)
        return false;

    if(req.uri.find("user=") != string::npos){
        startPos = req.uri.find("user=");
        endPos = req.uri.find("&", startPos);
        string usernameInURL = "";
        if(endPos == string::npos)
            usernameInURL = req.uri.substr(startPos+5);
        else
            usernameInURL = req.uri.substr(startPos+5, endPos-(startPos+5));

        if(usernameInURL != username || usernameInURL != req.username){
            return false;
        }
        fprintf(stderr, "URL contains username: %s\n", usernameInURL.c_str());
    }else{
        fprintf(stderr, "URL does not contain username\n");
    }    
    return true;
}

void RootHandler::handleRequest(HttpRequest &req)
{
    fprintf(stderr, "[%d] Hanlding request in RootHandler:\n", req.socket_fd);
    if (req.method == "GET")
    {
        HttpResponse res(req);
        // if supplies the correct sessionID cookie, no need to login again
        if (isCookieValid(req))
        {
            res.setStatus(302);
            string cookie = req.headers["Cookie"];
            size_t startPos = cookie.find("username=");
            size_t endPos = cookie.find(";", startPos);
            string username = cookie.substr(startPos + 9, endPos - (startPos + 9));

            res.setHeader("Location", "/home?user=" + username);
            string body = "";
            res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
            res.setHeader(CONTENT_LEN, to_string(body.length()));
            res.setBody(body);

            res.send();
        }
        else
        {
            res.setStatus(302);
            res.setHeader("Location", "/login");
            string body = "";
            res.setHeader(CONTENT_TYPE, "text/plain");
            res.setHeader(CONTENT_LEN, to_string(body.length()));
            res.setBody(body);

            res.send();
        }
    }
}

void LoginHandler::handleRequest(HttpRequest &req)
{
    fprintf(stderr, "[%d] Hanlding request in LoginHandler:\n", req.socket_fd);
    if (req.method == "GET")
    {
        HttpResponse res(req);
        res.setStatus(200);

        string body = readFiles("./pages/login.html");
        res.setBody(body);
        res.setHeader(CONTENT_TYPE, "text/html; charset=utf-8");
        res.setHeader(CONTENT_LEN, to_string(body.length()));
        res.send();
    }
    else if (req.method == "POST")
    {
        HttpResponse res(req);
        size_t startPos = req.content.find("username=");
        size_t endPos = req.content.find("&");
        string username = req.content.substr(startPos + 9, endPos - (startPos + 9));
        startPos = req.content.find("password=");
        string password = req.content.substr(startPos + 9);
        // Authentication & Cookie
        /*
        1) retrieve user info from backend
            - if password matches
                - create a new cookie sid
                - include in response to user
                    - set-cookie: sessionID=unique sid (with expiration date)
                - update to backend (PUT? CPUT?)
                - response status = 200
            - otherwise
                - response status = 401
            - send response back to user

        */
        // Retrieve user password from backend KV
        string passwordKV = "";
        // Connect to specific backend worker
        int workerfd = connectToKVS();

        backendMessage getMsgResp = sendToKVS("http", backendMessage::requestType::GET, USER_TABLE, username, "pwd", "", "", workerfd);

        if (getMsgResp.getRspMsg().status == backendMessage::responseType::OK)
        {
            passwordKV = getMsgResp.getRspMsg().content;
        }
        else
        {
            res.setStatus(404);
            string body = "User not found...";
            res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
            res.setHeader(CONTENT_LEN, to_string(body.length()));
            res.setBody(body);
            res.send();
            return;
        }

        // generate new user session ID (based on date time??)
        string digestFeed = getGMT();
        // compute unique ID using MD5
        unsigned char *digestBuffer = (unsigned char *)calloc(MD5_DIGEST_LENGTH, 1);
        char *data = new char[digestFeed.length() + 1];
        strcpy(data, digestFeed.c_str());
        computeSessionDigest(data, digestFeed.length(), digestBuffer);
        string SID = "";
        for (size_t i = 0; i != 16; ++i)
        {
            SID += "0123456789ABCDEF"[digestBuffer[i] / 16];
            SID += "0123456789ABCDEF"[digestBuffer[i] % 16];
        }
        // fprintf(stderr, "feed = %s\n -> SID = %s\n", digestFeed.c_str(), SID.c_str());

        if (password != passwordKV)
        {
            // send 401 response
            res.setStatus(401);
            string body = "Invalid credentials, please try again!";
            res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
            res.setHeader(CONTENT_LEN, to_string(body.length()));
            res.setBody(body);
            res.send();
        }
        else
        {

            int workerfd = connectToKVS();
            backendMessage putMsgRep = sendToKVS("http", backendMessage::requestType::PUT, USER_TABLE, username, "sid", "", SID, workerfd);

            if (putMsgRep.getRspMsg().status == backendMessage::responseType::OK)
            {
                // send 200 response with Cookie
                res.setStatus(200);
                // res.setHeader("Location", "/home");
                string body = "Welcome back " + username + "! Redirecting you to home in a moment...";
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(body.length()));
                // sid = unique 16-bit SID; username = username
                res.setHeader(SET_COOKIE, "sid=" + SID + ";username=" + username);
                res.setBody(body);

                res.send();

                req.sid = SID;
                req.username = username;
            }
            else
            {
                res.setStatus(500);
                string error_msg = putMsgRep.getRspMsg().content;
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(error_msg.length()));
                res.setBody(error_msg);
                res.send();
            }
        }
    }
}

void HomeHandler::handleRequest(HttpRequest &req)
{
    if(!isCookieValid(req)){
        HttpResponse res(req);
        res.setStatus(302);
        res.setHeader("Location", "/login");
        string body = "";
        res.setHeader(CONTENT_TYPE, "text/plain");
        res.setHeader(CONTENT_LEN, to_string(body.length()));
        res.setBody(body);

        res.send();
        return;
    }
    fprintf(stderr, "[%d] Hanlding request in HomeHandler:\n", req.socket_fd);
    if (req.method == "GET")
    {
        HttpResponse res(req);
        res.setStatus(200);

        string body = readFiles("./pages/home.html");
        res.setBody(body);
        res.setHeader(CONTENT_TYPE, "text/html; charset=utf-8");
        res.setHeader(CONTENT_LEN, to_string(body.length()));
        res.send();
    }
}

void MailHandler::handleRequest(HttpRequest &req)
{
    if(!isCookieValid(req)){
        HttpResponse res(req);
        res.setStatus(302);
        res.setHeader("Location", "/login");
        string body = "";
        res.setHeader(CONTENT_TYPE, "text/plain");
        res.setHeader(CONTENT_LEN, to_string(body.length()));
        res.setBody(body);

        res.send();
        return;
    }
    fprintf(stderr, "[%d] Hanlding request in MailHandler:\n", req.socket_fd);
    if (req.method == "GET")
    {
        HttpResponse res(req);
        res.setStatus(200);

        string body = readFiles("./pages/pennmail.html");
        res.setBody(body);
        res.setHeader(CONTENT_TYPE, "text/html; charset=utf-8");
        res.setHeader(CONTENT_LEN, to_string(body.length()));
        res.send();
    }
}

void DriveHandler::handleRequest(HttpRequest &req)
{
    if(!isCookieValid(req)){
        HttpResponse res(req);
        res.setStatus(302);
        res.setHeader("Location", "/login");
        string body = "";
        res.setHeader(CONTENT_TYPE, "text/plain");
        res.setHeader(CONTENT_LEN, to_string(body.length()));
        res.setBody(body);

        res.send();
        return;
    }
    fprintf(stderr, "[%d] Hanlding request in DriveHandler:\n", req.socket_fd);
    if (req.method == "GET")
    {
        HttpResponse res(req);
        res.setStatus(200);

        string body = readFiles("./pages/penndrive.html");
        res.setBody(body);
        res.setHeader(CONTENT_TYPE, "text/html; charset=utf-8");
        res.setHeader(CONTENT_LEN, to_string(body.length()));
        res.send();
    }
}

unordered_map<string,int> backendWorkerFDs={
   {"127.0.0.1:10001", -1},
   {"127.0.0.1:10002", -1},
   {"127.0.0.1:10003", -1},
   {"127.0.0.1:10004", -1},
   {"127.0.0.1:10005", -1},
   {"127.0.0.1:10006", -1},
};
void AdminHandler::handleRequest(HttpRequest &req)
{
    fprintf(stderr, "[%d] Hanlding request in AdminHandler:\n", req.socket_fd);
    if (req.method == "GET")
    {
        HttpResponse res(req);
        res.setStatus(200);

        string body = readFiles("./pages/admin.html");
        res.setBody(body);
        res.setHeader(CONTENT_TYPE, "text/html; charset=utf-8");
        res.setHeader(CONTENT_LEN, to_string(body.length()));
        res.send();
    }
    else if (req.method == "SHUTDOWN")
    {
        HttpResponse res(req);
        string targetAddr = req.content;
        size_t startPos = targetAddr.find(":");
        string targetPort = targetAddr.substr(startPos + 1);

        // initialize backendMessage object
        backendMessage shutdownMsg = backendMessage(backendMessage::Shutdown, "1", 1);
        vector<char> buffer;
        shutdownMsg.serialize(buffer);

        // set up socket
        backendWorkerFDs[targetAddr] = socket(PF_INET, SOCK_STREAM, 0);
        struct sockaddr_in workeraddr;
        bzero(&workeraddr, sizeof(workeraddr));
        workeraddr.sin_family = AF_INET;
        workeraddr.sin_port = htons(stoi(targetPort));
        inet_pton(AF_INET, "127.0.0.1", &(workeraddr.sin_addr));
        connect( backendWorkerFDs[targetAddr], (struct sockaddr *)&workeraddr, sizeof(workeraddr));

        // send shutdown msg
        int writeBytes = write( backendWorkerFDs[targetAddr], buffer.data(), buffer.size());
         fprintf(stderr, "Shutdown msg send to fd:[%d] -> ip:[%s]\n", backendWorkerFDs[targetAddr], targetAddr.c_str());
        
        res.setStatus(200);
        string body = "Successfully shut down storage node @ " + targetAddr;
        res.setBody(body);
        res.setHeader(CONTENT_TYPE, "text/html; charset=utf-8");
        res.setHeader(CONTENT_LEN, to_string(body.length()));
        res.send();
    }
    else if (req.method == "RESTART")
    {
        HttpResponse res(req);
        string targetAddr = req.content;
        size_t startPos = targetAddr.find(":");
        string targetPort = targetAddr.substr(startPos + 1);

        // initialize backendMessage object
        backendMessage restartMsg = backendMessage(backendMessage::Restart, "1", 1);
        vector<char> buffer;
        restartMsg.serialize(buffer);

        /*
        // set up socket
        int sockfd = socket(PF_INET, SOCK_STREAM, 0);
        struct sockaddr_in workeraddr;
        bzero(&workeraddr, sizeof(workeraddr));
        workeraddr.sin_family = AF_INET;
        workeraddr.sin_port = htons(stoi(targetPort));
        inet_pton(AF_INET, "127.0.0.1", &(workeraddr.sin_addr));
        connect(sockfd, (struct sockaddr*)&workeraddr, sizeof(workeraddr));
        */
        // send shutdown msg
        int writeBytes = write( backendWorkerFDs[targetAddr], buffer.data(), buffer.size());
        fprintf(stderr, "Restart msg send to fd:[%d] -> ip:[%s]\n", backendWorkerFDs[targetAddr], targetAddr.c_str());
        res.setStatus(200);
        string body = "Successfully restarted storage node @ " + targetAddr;
        res.setBody(body);
        res.setHeader(CONTENT_TYPE, "text/html; charset=utf-8");
        res.setHeader(CONTENT_LEN, to_string(body.length()));
        res.send();
    }
    else if (req.method == "GETINFO")
    {
        
        HttpResponse res(req);
        int coordfd = connectToCoord();
        backendMessage getInfoReq = backendMessage(backendMessage::GetInfoReq, "", 1);
        vector<char> outBuf;
        getInfoReq.serialize(outBuf);
        int writeBytes = write(coordfd, outBuf.data(), outBuf.size());
        char *inBuf = (char*) malloc(8000);
        int readBytes = read(coordfd, inBuf, 8000);
        backendMessage getInfoResp = backendMessage();
        getInfoResp.deserialize(inBuf, readBytes);
        string body = "";
        fprintf(stderr, "getInfoResp serverInfo size: %ld\n", getInfoResp.getGetInfoRspMsg().serverInfo.size());
        for(auto pair : getInfoResp.getGetInfoRspMsg().serverInfo){
            body += "IP=";
            body += pair.first;
            body += "&Status=";
            body += pair.second;
            body +="\n";
        }
        fprintf(stderr, "getInfo Result: %s\n", body.c_str());
        res.setStatus(200);
        res.setBody(body);
        res.setHeader(CONTENT_TYPE, "text/html; charset=utf-8");
        res.setHeader(CONTENT_LEN, to_string(body.length()));
        res.send();

        free(inBuf);
        close(coordfd);
    }
}

void RetrieveHandler::handleRequest(HttpRequest &req)
{
    fprintf(stderr, "[%d] Hanlding request in RetriveHandler:\n", req.socket_fd);
    if (req.method == "GET")
    {
        HttpResponse res(req);
        size_t startPos = req.uri.find("user=");
        size_t endPos = req.uri.find("&");
        string username = req.uri.substr(startPos + 5, endPos - (startPos + 5));
        startPos = req.uri.find("type=");
        endPos = req.uri.find("&", startPos);
        string type = req.uri.substr(startPos + 5, endPos - (startPos + 5));
        fprintf(stderr, "URI type = %s\n", type.c_str());
        if (type == "mbox")
        {

            vector<struct uidl_return> uidl_result = uidl(username);
            if (uidl_result.size() == 0)
            {
                res.setStatus(404);
                string body = "No emails found...";
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(body.length()));
                res.setBody(body);
                res.send();
                return;
            }

            // print uidl_result
            for (int i = 0; i < uidl_result.size(); i++)
            {
                fprintf(stderr, "Email %d: %s\n", i, uidl_result[i].hash_id.c_str());
                fprintf(stderr, "Email %d: %s\n", i, uidl_result[i].subject.c_str());
                fprintf(stderr, "Email %d: %s\n", i, uidl_result[i].sender.c_str());
                fprintf(stderr, "Email %d: %s\n", i, uidl_result[i].date.c_str());
            }

            stringstream ss;

            // Start building the JSON string
            ss << "{";
            ss << R"("emails": [)";

            // Add email objects
            for (int i = 0; i < uidl_result.size(); i++)
            {
                if (i > 0)
                {
                    ss << ",";
                }
                ss << "{";
                ss << R"("id": ")" << uidl_result[i].hash_id << R"(",)";
                ss << R"("subject": ")" << uidl_result[i].subject << R"(",)";
                ss << R"("date": ")" << uidl_result[i].date << R"(",)";
                ss << R"("sender": ")" << uidl_result[i].sender << R"(")";
                ss << "}";
            }

            // Close the JSON string
            ss << "]}";

            // Get the constructed JSON string
            string body = ss.str();

            res.setBody(body);
            res.setStatus(200);
            res.setHeader(CONTENT_TYPE, "application/json; charset=utf-8");
            res.setHeader(CONTENT_LEN, to_string(body.length()));
            res.send();
        }
        else if (type == "mail")
        {
            startPos = req.uri.find("id=");
            string emailId = req.uri.substr(startPos + 3);
            // string content = "Fake email body of email with ID = " + emailId;
            fprintf(stderr, "User %s Attempt to retrieve email: %s\n", username.c_str(), emailId.c_str());
            string content = retr(username, emailId);
            stringstream ss;
            // print username emailId
            uidl_return email_info = extract_uidl_info(content, emailId);

            // get the actual content
            // get the subject start pos
            size_t startPos = content.find("Subject: ");
            // get the end pos
            size_t endPos = content.find("\n", startPos);

            size_t content_start_pos = endPos + 1;
            // get the end pos
            std::string msg_body = content.substr(content_start_pos);

            // Start building the JSON string
            std::string::size_type pos = 0;
            while ((pos = msg_body.find("\n", pos)) != std::string::npos)
            {
                msg_body.replace(pos, 1, "\\\\n");
                pos += 3;
            }

            ss << "{";
            ss << R"("id": ")" << emailId << R"(",)";
            ss << R"("subject": ")" << email_info.subject << R"(",)";
            ss << R"("date": ")" << email_info.date << R"(",)";
            ss << R"("sender": ")" << email_info.sender << R"(",)";
            ss << R"("body": ")" << msg_body << R"(")";
            ss << "}";

            string body = ss.str();

            res.setBody(body);
            res.setStatus(200);
            res.setHeader(CONTENT_TYPE, "application/json; charset=utf-8");
            res.setHeader(CONTENT_LEN, to_string(body.length()));
            res.send();
        }
        else if (type == "dir")
        {
            int workerfd = connectToKVS();
            backendMessage getRowMsgResp = sendToKVS("http", backendMessage::requestType::GETROW, FILE_TABLE, username, "", "", "", workerfd);
            if (getRowMsgResp.getRspMsg().status == backendMessage::responseType::OK)
            {
                // extract all columns
                // string columns = getRowMsgResp.getRspMsg().content;
                res.setStatus(200);
                string resp_body = getRowMsgResp.getRspMsg().content;
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                fprintf(stderr, "getRowResp Content: %s", resp_body.c_str());
                res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
                res.setBody(resp_body);
                res.send();
            }
            else if (getRowMsgResp.getRspMsg().status == backendMessage::responseType::ERR)
            {
                res.setStatus(200);
                string resp_body = "./\n";
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                fprintf(stderr, "getRowResp Content: %s", resp_body.c_str());
                res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
                res.setBody(resp_body);
                res.send();
            }
        }
        else
        {
            // retrieve files from KVStore -> type is filename to retrieve
            int workerfd = connectToKVS();
            backendMessage getMsgResp = sendToKVS("http", backendMessage::requestType::GET, FILE_TABLE, username, type, "", "", workerfd);
            fprintf(stderr, "User %s Attempt to download file: %s\n", username.c_str(), type.c_str());
            if(getMsgResp.getRspMsg().status == backendMessage::responseType::OK) {
                res.setStatus(200);
                string resp_body = getMsgResp.getRspMsg().content;
                string MIMEtype = getMimeType(type);
                res.setHeader(CONTENT_TYPE, MIMEtype);

                res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
                res.setBody(resp_body);
                res.send();
            }
            else
            {
                res.setStatus(404);
                string body = "User file not found...";
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(body.length()));
                res.setBody(body);
                res.send();
            }
        }
    }
}

void SendHandler::handleRequest(HttpRequest &req)
{
    if (req.method == "POST")
    {
        HttpResponse res(req);
        size_t startPos = req.uri.find("type=");
        size_t endPos = req.uri.find("&", startPos);
        string dataType = req.uri.substr(startPos + 5, endPos - (startPos + 5));
        if (dataType == "mail")
        {
            // // extract FROM
            // size_t startPos = req.content.find("from=");
            // size_t endPos = req.content.find("&");
            // string from = req.content.substr(startPos+5, endPos-(startPos+5));
            // // extract TO
            // startPos = req.content.find("to=");
            // endPos = req.content.find("&", startPos);
            // string to = req.content.substr(startPos+3, endPos-(startPos+3));
            // // extract SUBJECT
            // startPos = req.content.find("subject=");
            // endPos = req.content.find("&", startPos);
            // string subject = req.content.substr(startPos+8, endPos-(startPos+8));
            // // extract BODY
            // startPos = req.content.find("body=");
            // string body = req.content.substr(startPos+5);
            // // get current DATE
            // time_t now = time(0);
            // char* dt = ctime(&now);

            size_t startPos = req.content.find("From: <");
            size_t endPos = req.content.find(">\n", startPos);
            string sender = req.content.substr(startPos + 7, endPos - (startPos + 7));

            startPos = req.content.find("To: <");
            endPos = req.content.find(">\n", startPos);
            string recp = req.content.substr(startPos + 5, endPos - (startPos + 5));
            vector<string> recpList;

            std::istringstream iss(recp);
            std::string token;

            // Split recp by ',' to get multiple recipients
            while (std::getline(iss, token, ','))
            {
                recpList.push_back(token);
            }

            fprintf(stderr, "Recipients: ");
            for (int i = 0; i < recpList.size(); i++)
            {
                fprintf(stderr, "%s, ", recpList[i].c_str());
            }

            startPos = req.content.find("Subject: ");
            endPos = req.content.find("\n", startPos);
            string subject = req.content.substr(startPos + 9, endPos - (startPos + 9));

            string body = req.content.substr(endPos + 1);

            int wrt_email_rsp = write_emails(STDOUT_FILENO, sender, recpList, req.content);
            // print wrt_email_rsp
            fprintf(stderr, "write email response: %d\n", wrt_email_rsp);

            // fprintf(stderr, "[%d] Sending new email:\n\tFROM: %s\n\tTO: %s\n\tDATE: %s\tSUBJECT: %s\n\tBODY: %s\n",
            //             req.socket_fd, from.c_str(), to.c_str(), dt, subject.c_str(), body.c_str());
            // TODO(!) parse receipient domain -> local or external
            // TODO(!) send email to local recipients

            // TODO(!) send email to external recipients
            if (wrt_email_rsp == 0)
            {
                res.setStatus(201);
                string resp_body = "Your mail to " + recp + " has been sent!"; // todo group sending
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
                res.setBody(resp_body);
            }
            else{
                // no such user
                res.setStatus(404);
                string resp_body = "Failed to send email to " + recp + "!";
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
                res.setBody(resp_body);
            }

            res.send();
        }
        else if (dataType == "file")
        {
            // extract username (no @localhost)
            size_t startPos = req.uri.find("user=");
            size_t endPos = req.uri.find("&", startPos);
            string userName = req.uri.substr(startPos + 5, endPos - (startPos + 5));
            // extract file name
            startPos = req.uri.find("filename=");
            string fileName = req.uri.substr(startPos + 9);
            // extract fileContent
            string fileContent = req.content;
            fprintf(stderr, "file content: %s\n", fileContent.c_str());

            fprintf(stderr, "file content length: %ld\n", fileContent.length());

            // send BackendMessage to backend coordinator
            int workerfd = connectToKVS();
            backendMessage putMsgRep = sendToKVS("http", backendMessage::requestType::PUT, FILE_TABLE, userName, fileName, "", fileContent, workerfd);
            fprintf(stderr, "User %s Attempt to upload file: %s\n", userName.c_str(), fileName.c_str());

            if (putMsgRep.getRspMsg().status == backendMessage::responseType::OK)
            {
                res.setStatus(201);
                string resp_body = "Uploaded new file!";
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
                res.setBody(resp_body);
                res.send();
            }
            else
            {
                res.setStatus(500);
                string error_msg = putMsgRep.getRspMsg().content;
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(error_msg.length()));
                res.setBody(error_msg);
                res.send();
            }
        }
        else if (dataType == "user")
        {
            // extract username & pwd
            size_t startPos = req.content.find('=');
            size_t endPos = req.content.find('&');
            string username = req.content.substr(startPos + 1, endPos - startPos - 1);
            string password = req.content.substr(endPos + 10);

            int workerfd = connectToKVS();
            backendMessage getMsgRep = sendToKVS("http", backendMessage::requestType::GET, USER_TABLE, username, "pwd", "", "", workerfd);

            if (getMsgRep.getRspMsg().status == backendMessage::responseType::OK)
            {
                res.setStatus(400);
                string resp_body = "Account already registered! Please log in with you credentials!";
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
                res.setBody(resp_body);
                res.send();
            }
            else
            {
                // TODO(!) how to differentiate from not found to error?
                int workerfd = connectToKVS();
                backendMessage putMsgRep = sendToKVS("http", backendMessage::requestType::PUT, USER_TABLE, username, "pwd", "", password, workerfd);

                if (putMsgRep.getRspMsg().status == backendMessage::responseType::OK)
                {
                    res.setStatus(201);
                    string resp_body = "Welcome " + username + "! You have succefully registered an account. Please log in with you credentials :)";
                    res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                    res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
                    res.setBody(resp_body);
                    res.send();
                }
                else
                {
                    res.setStatus(500);
                    string error_msg = putMsgRep.getRspMsg().content;
                    res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                    res.setHeader(CONTENT_LEN, to_string(error_msg.length()));
                    res.setBody(error_msg);
                    res.send();
                }
            }
        }
    }
    else if (req.method == "DELETE")
    {
        HttpResponse res(req);
        size_t startPos = req.uri.find("type=");
        size_t endPos = req.uri.find("&", startPos);
        string dataType = req.uri.substr(startPos + 5, endPos - (startPos + 5));
        if (dataType == "mail")
        {
            // extract username
            size_t startPos = req.content.find("username=");
            size_t endPos = req.content.find("&");
            string username = req.content.substr(startPos + 9, endPos - (startPos + 9));
            // extract email uid
            startPos = req.content.find("uid=");
            string uid = req.content.substr(startPos + 4);
            backendMessage::responseType dele_rsp = dele(username, uid);
            if (dele_rsp == backendMessage::responseType::OK)
            {
                res.setStatus(200);
                string resp_body = "Deleted email " + uid + "successfully !";
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
                res.setBody(resp_body);
                res.send();
            }
            else
            {
                res.setStatus(500);
                string error_msg = "Failed to delete email " + uid;
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(error_msg.length()));
                res.setBody(error_msg);
                res.send();
            }
        }
    }
}

void DeleteHandler::handleRequest(HttpRequest &req)
{
    if (req.method == "DELETE")
    {
        HttpResponse res(req);
        size_t startPos = req.uri.find("type=");
        size_t endPos = req.uri.find("&", startPos);
        string dataType = req.uri.substr(startPos + 5, endPos - (startPos + 5));
        if (dataType == "file")
        {
            // extract username (no @localhost)
            size_t startPos = req.uri.find("user=");
            size_t endPos = req.uri.find("&", startPos);
            string userName = req.uri.substr(startPos + 5, endPos - (startPos + 5));
            // extract file name
            startPos = req.uri.find("filename=");
            string fileName = req.uri.substr(startPos + 9);

            // send BackendMessage to backend coordinator
            int workerfd = connectToKVS();
            backendMessage deleteMsgRep = sendToKVS("http", backendMessage::requestType::DELETE, FILE_TABLE, userName, fileName, "", "", workerfd);
            fprintf(stderr, "User %s Attempt to delete file: %s\n", userName.c_str(), fileName.c_str());
            if (deleteMsgRep.getRspMsg().status == backendMessage::responseType::OK)
            {
                res.setStatus(200);
                string resp_body = "Deleted file " + fileName + "successfully !";
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
                res.setBody(resp_body);
                res.send();
            }
            else
            {
                res.setStatus(500);
                string error_msg = deleteMsgRep.getRspMsg().content;
                res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
                res.setHeader(CONTENT_LEN, to_string(error_msg.length()));
                res.setBody(error_msg);
                res.send();
            }
        }
    }
}

void MoveHandler::handleRequest(HttpRequest& req){
    if(req.method == "PUT") {
        HttpResponse res(req);
        // extract username
        size_t startPos = req.uri.find("user=");
        size_t endPos = req.uri.find("&", startPos);
        string userName = req.uri.substr(startPos+5, endPos-(startPos+5));
        // extract old file name
        startPos = req.uri.find("old=");
        endPos = req.uri.find("&", startPos);
        string oldFileName = req.uri.substr(startPos+4, endPos-(startPos+4));
        // extract new file name
        startPos = req.uri.find("new=");
        string newFileName = req.uri.substr(startPos+4);

        // 1) GET old file from KVS
        int workerfd = connectToKVS();
        backendMessage getMsgResp = sendToKVS("http", backendMessage::requestType::GET, FILE_TABLE, userName, oldFileName, "", "", workerfd);
        fprintf(stderr, "User %s Attempt to download file: %s\n", userName.c_str(), oldFileName.c_str());
        if(getMsgResp.getRspMsg().status == backendMessage::responseType::OK) {
            // 2) PUT new file to KVS
            workerfd = connectToKVS();
            backendMessage putMsgResp = sendToKVS("http", backendMessage::requestType::PUT, FILE_TABLE, userName, newFileName, "", getMsgResp.getRspMsg().content, workerfd);
            fprintf(stderr, "User %s Attempt to upload file: %s\n", userName.c_str(), newFileName.c_str());
            if(putMsgResp.getRspMsg().status == backendMessage::responseType::OK) {
                workerfd = connectToKVS();
                backendMessage deleteMsgResp = sendToKVS("http", backendMessage::requestType::DELETE, FILE_TABLE, userName, oldFileName, "", "", workerfd);
                fprintf(stderr, "User %s Attempt to delete file: %s\n", userName.c_str(), oldFileName.c_str());
                if(deleteMsgResp.getRspMsg().status == backendMessage::responseType::OK){
                    res.setStatus(200);
                    string resp_body = "Succefully changed file name: " + oldFileName + " -> " + newFileName + "\n";
                    
                    res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
                    res.setBody(resp_body);
                    res.send();
                    return;
                }
            }
        }
        res.setStatus(500);
        string resp_body = "Failed to change file name: " + oldFileName + " -> " + newFileName + "\n";
        
        res.setHeader(CONTENT_LEN, to_string(resp_body.length()));
        res.setBody(resp_body);
        res.send();
    }
}

void MiscHandler::handleRequest(HttpRequest &req)
{
    fprintf(stderr, "[%d] Hanlding request in MiscHandler:\n", req.socket_fd);
    HttpResponse res(req);
    res.setStatus(404);
    string body = "Not supported...";
    res.setHeader(CONTENT_TYPE, "text/plain; charset=utf-8");
    res.setHeader(CONTENT_LEN, to_string(body.length()));
    res.setBody(body);

    res.send();
}