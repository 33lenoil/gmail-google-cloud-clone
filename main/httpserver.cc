#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <cerrno>
#include <arpa/inet.h>
#include <pthread.h>
#include <string>
#include <string.h>
#include <unordered_map>
#include <algorithm>
#include <signal.h>

#include "http-request.h"
#include "http-response.h"
#include "request-handler.h"
#include "utils.h"

using namespace std;

// max size of buffer
#define BUFSIZE 20480 
// default port number
#define PORTNO 8000
// max number of concurrent clients
#define MAXTHREADS 100


RequestHandler* rootHandler = new RootHandler();
RequestHandler* loginHandler = new LoginHandler();
RequestHandler* homeHandler = new HomeHandler();
RequestHandler* mailHandler = new MailHandler();
RequestHandler* driveHandler = new DriveHandler();
RequestHandler* adminHandler = new AdminHandler();
RequestHandler* retrieveHandler = new RetrieveHandler();
RequestHandler* sendHandler = new SendHandler();
RequestHandler* deleteHandler = new DeleteHandler();
RequestHandler* moveHandler = new MoveHandler();
RequestHandler* miscHandler = new MiscHandler();
unordered_map<string, RequestHandler*> handler_map = {
  {"/", rootHandler},
  {"/login", loginHandler},
  {"/home", homeHandler},
  {"/pennmail", mailHandler},
  {"/penndrive", driveHandler},
  {"/admin", adminHandler},
  {"/retrieve", retrieveHandler}, // retrieve from Backend KV
  {"/send", sendHandler},         // send to Backend KV
  {"/delete", deleteHandler},         // delete from Backend KV
  {"/move", moveHandler},         // delete from Backend KV
  
  // TODO(!) more uri
};


// flag for verbose mode
bool vflag = false;
// thread ids
unordered_map<pthread_t, int> thread_map;

// helper functions
void *worker(void *args);
void print_request_line(int fd, char* cmd);
void sighandler(int signum);
// void reqhandler(HttpRequest req); 

int main(int argc, char *argv[])
{
  int c;
  int portno = PORTNO;
  while((c = getopt(argc, argv, "p:av")) != -1) {
    int tempPortno;  
    char *endptr = NULL;
    const char *nptr = optarg;
    switch(c) {
      case 'p':
        errno = 0;
        tempPortno = strtol(nptr, &endptr, 10);
        if(tempPortno >= 0 && errno == 0 && nptr && !*endptr) {
          portno = tempPortno;
        } else {
          fprintf(stderr, "Please follow the syntax [-p <portno>]\n");
          return 1;
        }
        break;
      case 'a':
        fprintf(stderr, "CIS 5050 SP24 T14\n");
        return 1;
      case 'v':
        vflag = true;
        break;
      case '?':
        if (optopt == 'p') {
          fprintf(stderr, "Option -%c requires an argument [-p <portno>]\n", optopt);
        } else {
          fprintf(stderr, "Unknown option, please follow the syntax %s [-p <portno>] [-a] [-v]\n", argv[0]);
        }
        return 1;
      default:
        return 1;
    }
  }
  // set signal handler
  struct sigaction sa;

  sa.sa_handler = sighandler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; /* do NOT restart functions if interrupted by handler */
  if (sigaction(SIGINT, &sa, NULL) < 0 || sigaction(SIGUSR1, &sa, NULL) < 0) {
    fprintf(stderr, "Fail to register signal handler: %s\n", strerror(errno));
    return 1;
  }
  // set up server socket
  int listen_fd = socket(PF_INET, SOCK_STREAM, 0);
  if(listen_fd < 0) {
    fprintf(stderr, "Fail to create socket: %s\n", strerror(errno));
    return 1;
  }
  // reuse the port to avoid "port in use" error
  int opt = 1;
  int ret = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, &opt, sizeof(opt));
  if (ret < 0) 
  {
    fprintf(stderr, "Fail to set up setsockopt: %s\n", strerror(errno));
    return 1;
  }
  // bind the socket to the specified portno
  struct sockaddr_in servaddr;
  bzero(&servaddr, sizeof(servaddr)); 
  servaddr.sin_family = AF_INET; 
  servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  servaddr.sin_port = htons(portno);
  ret = bind(listen_fd, (struct sockaddr*)&servaddr, sizeof(servaddr));
  if (ret < 0) 
  {
    fprintf(stderr, "Fail to bind: %s\n", strerror(errno));
    return 1;
  }
  // listening for connection requests
  ret = listen(listen_fd, 100);
  if (ret < 0) 
  {
    fprintf(stderr, "Fail to listen: %s\n", strerror(errno));
    return 1;
  }
  if(vflag) fprintf(stderr, "[%d] Frontend Node listining on port %d\n", listen_fd, portno);
  while(true) {
    // wait & remove exited threads
    for(auto p : thread_map) {
      void *status;
      if(p.second == -1) {
        pthread_join(p.first, &status);
        thread_map.erase(p.first);
      }
    }
    if(thread_map.size() >= MAXTHREADS) continue;
    struct sockaddr_in clientaddr;
    socklen_t clientaddrlen = sizeof(clientaddr);
    int *client_fd = (int*)malloc(sizeof(int));
    *client_fd = accept(listen_fd, (struct sockaddr*)&clientaddr, &clientaddrlen);

    // create the thread
    pthread_t tid;
    pthread_create(&tid, NULL, worker, client_fd);
    // update the active (thread id, connection fd) thread_map
    thread_map.insert({tid, *client_fd});
  }

  return 0;
}

void *worker(void *args) {
  // block SIGINT
  sigset_t sigset;
  sigemptyset(&sigset);
  sigaddset(&sigset, SIGINT);
  pthread_sigmask(SIG_BLOCK, &sigset, nullptr);

  int client_fd = *(int *)args;
  if(vflag) fprintf(stderr, "[%d] New connection\n", client_fd);

  /* Persistent Connection until
    1) Received Connection: close header from client
    2) read() from client_fd returns 0
  */
  bool connection_alive = true;
  string sessionID = "";
  string loggedInUser = "";
  while(true) {
    // parse request
    HttpRequest req(client_fd, vflag, connection_alive);
    if(vflag) {
      fprintf(stderr, "[%d] Received request:\n", client_fd);
      req.print();
    }
    
    // handle request
    if(req.valid) {
      size_t endPos = req.uri.find("?");
      string uri = req.uri;
      if(endPos != string::npos){
        uri = req.uri.substr(0, endPos);
      }
      if(handler_map.find(uri) != handler_map.end()){
        if(uri == "/admin") {
          if(req.method == "GET"){
            if(req.uri == "/admin?type=load"){
              //fprintf(stderr, "OPTIONS header: %s\n", req.headers["Access-Control-Request-Method"].c_str());
              // redirect to loadBalancer to access admin console
              HttpResponse res(req);
              res.setStatus(200);
              string body = to_string(thread_map.size());
              res.setHeader(CONTENT_TYPE, "text/plain");
              res.setHeader(ACCESS_CONTROL_ALLOW_ORIGIN, "http://127.0.0.1:8000");
              res.setHeader(CONTENT_LEN, to_string(body.length()));
              res.setBody(body);

              res.send();
              
            } else {
              // redirect to loadBalancer to access admin console
              HttpResponse res(req);
              res.setStatus(302);
              res.setHeader("Location", "http://127.0.0.1:8000/admin");
              string body = "";
              res.setHeader(CONTENT_TYPE, "text/plain");
              res.setHeader(CONTENT_LEN, to_string(body.length()));
              res.setBody(body);

              res.send();
              
            }
          }else{
            miscHandler->handleRequest(req);
          }
          
        }else{
          // include the session ID (if any) in the request
          req.sid = sessionID;
          req.username = loggedInUser;
          handler_map[uri]->handleRequest(req);
          if(uri == "/login" && req.method == "POST") {
            // TODO(!) might need to actually retrieve from KV with multiple frontend node
            // store the session ID for the current connection
            sessionID = req.sid;
            loggedInUser = req.username;
            if(vflag) {
              fprintf(stderr, "[%d] Attempted login from user with session cookie (empty if failed login): %s\n", client_fd, sessionID.c_str());
            }
          }
        }
      }else if(uri != ""){
        miscHandler->handleRequest(req);
      }
    }

    if(connection_alive == false) {
      // revoke old session cookie
      if(vflag) {
        fprintf(stderr, "[%d] Revoked session cookie: %s\n", client_fd, sessionID.c_str());
      }
      sessionID = "";
      loggedInUser = "";
      // close connection
      if(vflag) fprintf(stderr, "[%d] Connection closed\r\n", client_fd);
      break;
    }
  }
  // close client fd
  close(client_fd);
  // update thread map
  thread_map[pthread_self()] = -1;
  // exit current worker thread
  pthread_exit(NULL);
}

void sighandler(int signum) {
  if(signum == SIGINT) {
    
    for(auto p : thread_map) {
      // send SIGUSR1 to all child threads
      pthread_kill(p.first, SIGUSR1);
    }
    void *status;
    for(auto p : thread_map){
      pthread_join(p.first, &status);
    }
    exit(1);
  }else if(signum == SIGUSR1) {
    
    int fd = thread_map[pthread_self()];
    // send +ERR msg to the client
    char msg[] = "-ERR Server shutting down\r\n";
    do_write(fd, msg, strlen(msg));
    if(vflag) fprintf(stderr, "[%d] S: %s", fd, msg);
    // close the current connection
    close(fd);
    if(vflag) fprintf(stderr, "[%d] Connection closed\r\n", fd);
    // exit the current thread
    pthread_exit(NULL);
  }
}