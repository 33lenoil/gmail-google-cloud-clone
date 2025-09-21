#ifndef BACKENDWORKER_H
#define BACKENDWORKER_H

#include <map>
#include <vector>
#include <string>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <chrono>
#include <iomanip>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <set>
#include <experimental/filesystem>
#include <ctype.h>
#include <openssl/md5.h>
#include <time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <tuple>
#include <sys/stat.h>
#include <deque>
#include <ctime>
#include <string.h>
#include <algorithm>

#include "backendMessage.h"

#define NUMTHREADS 100

namespace fs = std::experimental::filesystem;

void ping();

void *pingWorker(void *);

void *coordWorker(void *);

void *worker(void *arg);

void sigHandler(int signal);

std::string computeDigest(std::string msg);

bool rebuildOffsets(std::map<std::string, std::map<std::string, uint64_t>> *currOffsets,
					pthread_mutex_t *currOffsetLock, std::string rowName, std::string tableName);

void putToTable(
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable,
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks,
	std::map<std::string, std::set<std::tuple<std::string, int>>> *currRawCols,
	std::map<std::string, pthread_mutex_t> *currRawColsLocks,
	std::string row, std::string col, std::string rawCol, std::string val, int isEnd,
	bool isAppend, off_t logOffset);

bool checkCputCond(
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable,
	std::string table, pthread_mutex_t *currLock,
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks,
	std::map<std::string, std::map<std::string, uint64_t>> *currOffsets,
	std::string row, std::string col, std::string val1, bool sendRsp,
	int commFd, int index);

void put(std::string table, std::string row, std::string col, std::string rawCol, std::string val,
		 int commFd, int index, int isEnd, off_t logOffset);

void append(std::string table, std::string row, std::string col, std::string rawCol,
			std::string val, int isEnd, off_t logOffset, int commFd, int index);

void appendOperation(std::map<std::string, std::map<std::string,
													std::tuple<std::string, int, off_t, std::string>>> *currTable,
					 std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks,
					 std::map<std::string, std::set<std::tuple<std::string, int>>> *currRawCols,
					 std::map<std::string, pthread_mutex_t> *currRawColsLocks,
					 std::string row, std::string col, std::string rawCol, std::string val,
					 int isEnd, off_t logOffset);

void get(std::string table, std::string row, std::string col,
		 int commFd, int index);

void cPut(std::string table, std::string row, std::string col, std::string rawCol, std::string val1,
		  std::string val2, int commFd, int index, int isEnd, off_t logOffset);

void verify(std::string row, std::string password, int commFd, int index);

void getRow(std::string table, std::string row, int commFd, int index);

std::string checkDeleteCond(
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable,
	std::map<std::string, std::map<std::string, uint64_t>> *currOffsets,
	pthread_mutex_t *currOffsetLock,
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks,
	std::string table, std::string row, std::string col);
void deleteOperation(
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable,
	std::map<std::string, std::map<std::string, uint64_t>> *currOffsets,
	pthread_mutex_t *currLock,
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks,
	std::map<std::string, std::set<std::tuple<std::string, int>>> *currRawCols,
	std::map<std::string, pthread_mutex_t> *currRawColsLocks,
	std::string table, std::string row, std::string col, std::string rawCol,
	off_t logOffset);
void deleteCell(std::string table, std::string row, std::string col, std::string rawCol, int commFd,
				int index, off_t logOffset);

void notify(backendMessage::requestType reqType, std::string sourceIpPort,
			std::string table, std::string row, std::string col, std::string rawCol, std::string val,
			int end, int commFd, int index, off_t logOffset);

void ack(std::string reqId, backendMessage::responseType status, int commFd,
		 int index);

bool writeToDisk(
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *inMemTable,
	std::map<std::string, std::map<std::string, uint64_t>> *offsetTable,
	std::map<std::string, std::set<std::tuple<std::string, int>>> rawColTable,
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *tableLocks,
	std::string table);

off_t logRequest(backendMessage request);

void performRequest(backendMessage request, int commFd, int index,
					off_t logOffset);

void parseAssignment(backendMessage::AssignMsg assignment);

void forwardToPeers(backendMessage msg, std::string ipPort);

bool doCheckpoint();
void updateLogFile();
std::vector<std::string> findLogFiles();

void doRecovery();
off_t recoverFromLocalLog(std::string oldLogFilePath, std::string tmpLogFilePath, std::string newLogFilePath);
off_t rebuildInMemTable(std::string filePath, off_t startOffset);
bool sendTableFiles(std::string tableName, int secondaryFd);
bool rmOutdatedFiles(std::string dir);

void cleanUpMsgIdMaps(std::string msgId);

void deliverRsp(int index);

void clearQueue();

void printTime();

void listOnDiskFiles();

// arguments for the threads
struct threadArgs
{
	int index;
	int fd;
};

bool verbose = false;

volatile bool shuttingDown = false;

bool pretend = false;

// primary or secondary
// std::string groupRole = "unassigned";

// primary for testing
std::string groupRole = "unassigned";
// ip:port of primary
std::string primaryIpPort;
// ip:port of secondaries
std::vector<std::string> secondaryIpPorts;
int secondariesReady = 0;

uint32_t cpVersion = 0;
bool isCheckpointing = false;
int numCPFinished = 0;
bool lastCPSuccess = false;
std::string logFilePath = "";
pthread_mutex_t logFileMutex;
pthread_mutex_t cpMutex;
bool isLogging = false;

std::string ownIp;
int ownPort;
int ownSocket;

std::string coordIp;
int coordPort;
int coordSocket;
char *coordBuffer;
// {ipPort : fd}
std::map<std::string, int> peerFdMap;

pthread_t threads[NUMTHREADS] = {0};
pthread_t pingThread = 0;
pthread_t coordThread = 0;

pthread_mutex_t lock;

std::string path;

volatile int fds[NUMTHREADS] = {0};

std::string msgIds[NUMTHREADS];

std::map<std::string, int> msgId2Index;

volatile int fdCount = 0;

struct threadArgs *args[NUMTHREADS];

char *buffers[NUMTHREADS] = {NULL};

// {rowName : colName : (operation, isEnd, logOffset, value)}
// the user info table and its locks
std::map<std::string,
		 std::map<std::string, std::tuple<std::string, int, off_t, std::string>>>
	userTable;
std::map<std::string, std::map<std::string, pthread_mutex_t>> userTableLocks;

// the file table and its locks
std::map<std::string,
		 std::map<std::string, std::tuple<std::string, int, off_t, std::string>>>
	fileTable;
std::map<std::string, std::map<std::string, pthread_mutex_t>> fileTableLocks;

// the inbox table and its locks
std::map<std::string,
		 std::map<std::string, std::tuple<std::string, int, off_t, std::string>>>
	inboxTable;
std::map<std::string, std::map<std::string, pthread_mutex_t>> inboxTableLocks;

int tablesSize = 0;

// the user info offset table and its locks
pthread_mutex_t userOffsetLock;
std::map<std::string, std::map<std::string, uint64_t>> userOffsets;

// the file offset table and its locks
pthread_mutex_t fileOffsetLock;
std::map<std::string, std::map<std::string, uint64_t>> fileOffsets;

// the inbox offset table and its locks
pthread_mutex_t inboxOffsetLock;
std::map<std::string, std::map<std::string, uint64_t>> inboxOffsets;

// the user info raw columns table and its locks
// {rowName : {(colName, ifDeleted)}}
std::map<std::string, std::set<std::tuple<std::string, int>>> userRawCols;
std::map<std::string, pthread_mutex_t> userRawColsLocks;

// the file raw columns table and its locks
std::map<std::string, std::set<std::tuple<std::string, int>>> fileRawCols;
std::map<std::string, pthread_mutex_t> fileRawColsLocks;

// the inbox raw columns table and its locks
std::map<std::string, std::set<std::tuple<std::string, int>>> inboxRawCols;
std::map<std::string, pthread_mutex_t> inboxRawColsLocks;

// queue and queue locks
std::deque<std::tuple<backendMessage, int, int, off_t>> queue;
pthread_mutex_t queueLock;

// outgoing queue and queue locks
// {(msg, ipPort)}
std::deque<std::tuple<backendMessage, std::string>> outQueue;
pthread_mutex_t outQueueLock;

std::map<std::string, int> msgId2ClientFd;

std::map<std::string, std::string> msgId2SourceIpPort;

// msgId to count
std::map<std::string, int> ackCounter;

std::map<std::string, pthread_mutex_t> counterLocks;

std::map<std::string, std::set<std::string>> tableRowMap;

std::string allColumnsName = computeDigest("AllColumns");
#endif