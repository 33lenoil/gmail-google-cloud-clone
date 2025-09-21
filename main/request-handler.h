#ifndef REQUEST_HANDLER_H
#define REQUEST_HANDLER_H

#include <string>
#include <string.h>
#include "http-request.h"
#include "http-response.h"

using namespace std;

struct sockaddr_in;

const static string USER_TABLE = "UserInfoTable";
const static string FILE_TABLE = "UserFileTable";
const static string MAIL_TABLE = "InboxTable";

class RequestHandler {
    public:
        static sockaddr_in backendCoordinatorAddr;
        static sockaddr_in backendWorkerAddr;
        virtual void handleRequest(HttpRequest& req) = 0;
};

/* / */ 
class RootHandler : public RequestHandler {
    public:
        void handleRequest(HttpRequest& req) override;
};

/* /login */
class LoginHandler : public RequestHandler {
    public:
        void handleRequest(HttpRequest& req) override;
};

/* /home */
class HomeHandler : public RequestHandler {
    public:
        void handleRequest(HttpRequest& req) override;
};

/* /pennmail */
class MailHandler : public RequestHandler {
    public:
        void handleRequest(HttpRequest& req) override;
};

/* /penndrive */
class DriveHandler : public RequestHandler {
    public:
        void handleRequest(HttpRequest& req) override;
};

/* /admin */
class AdminHandler : public RequestHandler {
    public:
        void handleRequest(HttpRequest& req) override;
};

/* /retrieve - retrieving data to smpt or backend 
** GET, HEAD
*/
class RetrieveHandler : public RequestHandler {
    public:
        void handleRequest(HttpRequest& req) override;
};

/* /send - sending data to smpt or backend 
** PUT
*/
class SendHandler : public RequestHandler {
    public:
        void handleRequest(HttpRequest& req) override;
};

/* /delete - deleting data from backend 
** DELETE
*/
class DeleteHandler : public RequestHandler {
    public:
        void handleRequest(HttpRequest& req) override;
};

/* /move - change file name at backend 
** PUT
*/
class MoveHandler : public RequestHandler {
    public:
        void handleRequest(HttpRequest& req) override;
};

/* all other uri */
class MiscHandler : public RequestHandler {
    public:
        void handleRequest(HttpRequest& req) override;
};

#endif /* REQUEST_HANDLER_H */