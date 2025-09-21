#include <string>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <string.h>
#include <ctime>
#include <arpa/inet.h>
#include "utils.h"
#include "email_utils.h"
#include <cmath>
#include <unordered_map>

using namespace std;

string readFiles(string filename){
    ifstream t(filename);
    stringstream buffer;
    buffer << t.rdbuf();
    return buffer.str();
}

bool do_write(int fd, char *buf, int len) {
  int sent = 0;
  while(sent < len) {
    int n = write(fd, &buf[sent], len-sent);
    if(n < 0){
      fprintf(stderr, "Fail to write: %s\n", strerror(errno));
      return false;
    }
    sent += n;
  }
  return true;
}

bool do_read(int fd, char *buf, int len) {
  int received = 0;
  while(received < len) {
    int n = read(fd, &buf[received], len-received);
    if(n <= 0){
      fprintf(stderr, "Fail to read: %s\n", strerror(errno));
      return false;
    }
    received += n;
  }
  return true;
}

string getGMT() {
  std::time_t currentTime = std::time(nullptr);
  std::tm* localTime = std::localtime(&currentTime);
  char buffer[80];
  std::strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", localTime);
  string result(buffer);
  return result;
}

void computeSessionDigest(char *data, int dataLengthBytes, unsigned char *digestBuffer)
{
  /* The digest will be written to digestBuffer, which must be at least MD5_DIGEST_LENGTH bytes long */

  MD5_CTX c;
  MD5_Init(&c);
  MD5_Update(&c, data, dataLengthBytes);
  MD5_Final(digestBuffer, &c);

  return;
}

/* return worker fd */
int connectToKVS() {
  // init backendCoordinator sockaddr_in
  int coordfd = socket(PF_INET, SOCK_STREAM, 0);
  struct sockaddr_in backendCoordinatorAddr;
  bzero(&backendCoordinatorAddr, sizeof(backendCoordinatorAddr)); 
  backendCoordinatorAddr.sin_family = AF_INET; 
  backendCoordinatorAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  backendCoordinatorAddr.sin_port = htons(10000);
  inet_pton(AF_INET, "127.0.0.1", &backendCoordinatorAddr.sin_addr);       
  // connect to the socket
  connect(coordfd, (struct sockaddr*)&backendCoordinatorAddr, sizeof(backendCoordinatorAddr)); 
  
  // send initial message to Coordinator to get redirection to Worker
  backendMessage initMsg = backendMessage(backendMessage::Req, "-1", 1);
  initMsg.setReqMsg(backendMessage::requestType::GET, "UserInfoTable", "admin", "pwd", "", "123456");
  vector<char> buffer;
  char *inBuf = (char*) malloc(4096);
  initMsg.serialize(buffer);

  // send msg to Coordinator to get worker redirection
  int writeBytes = write(coordfd, buffer.data(), buffer.size());
  // read redirection instruction from Coordinator
  int readBytes = read(coordfd, inBuf, 4096);
  // parse delegated Worker IP
  backendMessage initMsgRep = backendMessage();
  initMsgRep.deserialize(inBuf, readBytes);
  initMsgRep.printMsg();
  fprintf(stderr, "line 97-----------\n");
  string ipPort = initMsgRep.getRedirMsg().ipPort;
  //fprintf(stderr, "Redirected to worker ip: %s\n", ipPort.c_str());
  // close Coordinator socket
  close(coordfd);
  free(inBuf);
  fprintf(stderr, "line101 connectToKVS: %s", ipPort.c_str());
  // init backendWorker sockaddr_in
  int workerfd = socket(PF_INET, SOCK_STREAM, 0);
  struct sockaddr_in backendWorkerAddr;
  bzero(&backendWorkerAddr, sizeof(backendWorkerAddr)); 
  backendWorkerAddr.sin_family = AF_INET; 
  backendWorkerAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  backendWorkerAddr.sin_port = htons(
    stoi(ipPort.substr(ipPort.find(":") + 1))
  );
  inet_pton(AF_INET, "127.0.0.1", &backendWorkerAddr.sin_addr);       
  // connect to the socket
  connect(workerfd, (struct sockaddr*)&backendWorkerAddr, sizeof(backendWorkerAddr)); 
  // return connected worker fd
  return workerfd;
}

/* return coord fd */
int connectToCoord() {
  // init backendCoordinator sockaddr_in
  int coordfd = socket(PF_INET, SOCK_STREAM, 0);
  struct sockaddr_in backendCoordinatorAddr;
  bzero(&backendCoordinatorAddr, sizeof(backendCoordinatorAddr)); 
  backendCoordinatorAddr.sin_family = AF_INET; 
  backendCoordinatorAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  backendCoordinatorAddr.sin_port = htons(10000);
  inet_pton(AF_INET, "127.0.0.1", &backendCoordinatorAddr.sin_addr);       
  // connect to the socket
  connect(coordfd, (struct sockaddr*)&backendCoordinatorAddr, sizeof(backendCoordinatorAddr)); 
  
  
  return coordfd;
}

// send backendMessage to backendWorker
// return response from the worker
backendMessage sendToKVS(string source, backendMessage::requestType reqType, string table, string row, string col, string matchVal, string newVal, int workerfd) {
  // generate random unique backendMessage ID
  string msg_id = computeHash(source + getCurrentTime() + newVal);
  // decide chunks
  int numChunks = ceil(newVal.size() / 6000.0 );
  fprintf(stderr, "numChunks: %d\n", numChunks);

  if( numChunks <= 1) {
    fprintf(stderr, "newVal: %s\n", newVal.c_str());
    backendMessage msg = backendMessage(backendMessage::Req, msg_id, 1);
    msg.setReqMsg(reqType, table, row, col, matchVal, newVal);
    vector<char> outBuf;
    msg.serialize(outBuf);
    int writeBytes = write(workerfd, outBuf.data(), outBuf.size());
    
    char *inBuf = (char*) malloc(10000);
    int readBytes = read(workerfd, inBuf, 10000);
    fprintf(stderr, "readBytes: %d\n", readBytes);
    backendMessage resp = backendMessage();
    bool success = resp.deserialize(inBuf, readBytes);
    fprintf(stderr, "success1: %d\n", success);
    int i = 1;
    fprintf(stderr, "--------[%d] Backend Response-------\n", i);
    resp.printMsg();
    string content = resp.getRspMsg().content;
    
    //fprintf(stderr, "isEnd: %d\n", resp.isEnd);
    bool finished = true;
    if(resp.isEnd == 0){
      finished = false;
    }
    
    while(!finished){
      i++;
      readBytes = read(workerfd, inBuf, 10000);
      backendMessage resp_temp = backendMessage();
      bool success = resp_temp.deserialize(inBuf, readBytes);
      fprintf(stderr, "success2: %d\n", success);
      fprintf(stderr, "--------[%d] Backend Append-------\n", i);
      resp.printMsg();
      
      content += resp_temp.getAppendMsg().appendMsg;
      if(resp_temp.isEnd == 1) finished = true;
    }
    fprintf(stderr, "------------------------------------\n");
    fprintf(stderr, "Final content: %s\n", content.c_str());
    fprintf(stderr, "Final content size: %ld\n", content.size());
    fprintf(stderr, "------------------------------------\n");
    // close Worker socket
    close(workerfd);
    free(inBuf);
    resp.setRspMsg(resp.getRspMsg().status, content);
    return resp;
  }else{
    for(int i = 0; i < numChunks; i++) {
      backendMessage msg;
      string chunk = newVal.substr(i*6000, 6000);
      if(i == 0){
        msg = backendMessage(backendMessage::Req, msg_id, 0);
        msg.setReqMsg(reqType, table, row, col, matchVal, chunk);
      }else if(i == numChunks-1){
        msg = backendMessage(backendMessage::Append, msg_id, 1);
        msg.setAppendMsg(table, row, col, chunk);
      }else{
         msg = backendMessage(backendMessage::Append, msg_id, 0);
         msg.setAppendMsg(table, row, col, chunk);
      }
      // string chunk = newVal.substr(i*4000, 4000);
      // msg.setReqMsg(reqType, table, row, col, matchVal, chunk);
      vector<char> outBuf;
      msg.serialize(outBuf);
      int writeBytes = write(workerfd, outBuf.data(), outBuf.size());
      fprintf(stderr, "write bytes: %d\n", writeBytes);
      // TODO(!) 只能从第一个chunk的response查OK？？
      backendMessage resp = backendMessage();
      if(i == 0){
        char *inBuf = (char*) malloc(4096);
        int readBytes = read(workerfd, inBuf, 4096);
        resp.deserialize(inBuf, readBytes);
        free(inBuf);
      }
      if(i == numChunks-1){
        close(workerfd);
        return resp;
      }
    }
  }

}

string getMimeType(string fileName) {
    // Get the file extension
    string extension;
    size_t dotIndex = fileName.find_last_of('.');
    if (dotIndex != string::npos) {
        extension = fileName.substr(dotIndex + 1);
        // Convert extension to lowercase
        for (char& c : extension) {
            c = tolower(c);
        }
    }

    // Define MIME types based on file extension
    unordered_map<string, string> mimeTypes = {
        {"txt", "text/plain"},
        {"html", "text/html"},
        {"css", "text/css"},
        {"js", "application/javascript"},
        {"json", "application/json"},
        {"xml", "application/xml"},
        {"pdf", "application/pdf"},
        {"doc", "application/msword"},
        {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {"xls", "application/vnd.ms-excel"},
        {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {"ppt", "application/vnd.ms-powerpoint"},
        {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {"zip", "application/zip"},
        {"gif", "image/gif"},
        {"jpeg", "image/jpeg"},
        {"jpg", "image/jpeg"},
        {"png", "image/png"},
        {"svg", "image/svg+xml"},
        {"bmp", "image/bmp"},
        {"tif", "image/tiff"},
        {"tiff", "image/tiff"}
        // Add more mappings as needed
    };

    // Look up the MIME type based on the file extension
    auto it = mimeTypes.find(extension);
    if (it != mimeTypes.end()) {
        return it->second;
    } else {
        return "application/octet-stream"; // Default MIME type for unknown files
    }
}