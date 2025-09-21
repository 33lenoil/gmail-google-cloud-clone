#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <dirent.h>
#include <openssl/md5.h>
#include "backendMessage.h"


using namespace std;

string readFiles(string filename);
bool do_write(int fd, char *buf, int len);
bool do_read(int fd, char *buf, int len);
string getGMT();
void computeSessionDigest(char *data, int dataLengthBytes, unsigned char *digestBuffer);
int connectToKVS();
int connectToCoord();
backendMessage sendToKVS(string source, backendMessage::requestType reqType, string table, string row, string col, string matchVal, string newVal, int workerfd);
string getMimeType(string fileName);
#endif /* UTILS_H */