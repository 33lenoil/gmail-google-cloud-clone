#include "backendMessage.h"
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/md5.h>
#include <functional>
#include <vector>
#include <queue>
#include <map>
#include <string.h>
#include <chrono>
#include <algorithm>
#include <signal.h>
#include <csignal>

#ifndef BACKENDCOORDINATOR_H
#define BACKENDCOORDINATOR_H

class ThreadPool {
  public:
    ThreadPool(size_t numThreads);
    ~ThreadPool();
    void enqueue(std::function<void()> task);
    bool isFull();
    void openConnection(int fd, char* buf);
    void closeConnection(int fd);
    bool isShutdown();
  private:
    static void* worker(void* arg);
    void* run();
    std::queue<std::function<void()>> tasks;
    pthread_mutex_t queueMutex;
    pthread_cond_t condition;
    std::vector<pthread_t> workers;
    size_t MAX_THREADS = 100;
    bool shutdown = false;
};

std::string computeDigest(std::string input);
void* auditWorker(void* arg);
void* checkPointInit(void* arg);
void handleConnection(int fd, char* buf);
void handlePingMsg(int fd, backendMessage msg);
void handleReqMsg(int fd, backendMessage msg);
void removeWorker(std::string workerId);

bool verbose = false;
ThreadPool* pool;
std::map<int, char*> activeConnections;
pthread_mutex_t actThreadsMutex;
pthread_mutex_t workerPingMutex;
pthread_t checkpointThread;
pthread_t auditWorkerThread;
time_t lastCP;
// {workerId: (workerStatus, groupId)}
std::map<std::string, std::pair<std::string, int>> workerStatus;
// {groupId: (primaryWorkerId, backupWorkerIds)}
std::map<int, std::pair<std::string, std::vector<std::string>>> groupWorkers;
// {groupId: (letterKeyPair, numKeyPair)}
// letterKeyPair, numKeyPair: <startKey, endKeyExclusive>
std::map<int, std::pair<std::pair<char, char>, std::pair<char, char>>> groupKeys;
// {groupId : groupSize}
std::map<int, int> groupSize;
// {groupId : workerIndexExecutedLastReq}
std::map<int, int> groupLastReq;
// {workerId: fds}: record the file descriptors for each worker
std::map<std::string, int> primary2Fds;
std::map<std::string, int> secondary2Fds;
// {fds: workerId}: record the file descriptors for each worker
std::map<int, std::string> fds2Primary;
std::map<int, std::string> fds2Secondary;
// {workerId: lastActiveTime}
std::map<std::string, time_t> workerLastPing;

#endif
