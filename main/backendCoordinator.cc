#include "backendCoordinator.h"

#define NUM_CONNECTIONS 100
#define BUFFER_SIZE 10000
#define CHECKPOINT_INTERVAL 50
#define AUDIT_WORKER_INTERVAL 6
#define WORKER_TIMEOUT 6

/*
  * Function to compute the md5 hash of a string
  * @param input: the string to be hashed
  * @return: the md5 hash of the input string
 */
std::string computeDigest(std::string input) {
	unsigned char digestBuffer[MD5_DIGEST_LENGTH];
	const char *data = input.c_str();
	MD5_CTX c;
	MD5_Init(&c);
	MD5_Update(&c, (const unsigned char*) data, input.length());
	MD5_Final(digestBuffer, &c);

	// hex string conversion
	std::string result;
	for (std::size_t i = 0; i != 16; i++) {
		result += "0123456789ABCDEF"[digestBuffer[i] / 16];
		result += "0123456789ABCDEF"[digestBuffer[i] % 16];
	}
	return result;
}

/*
  * Constructor for the thread pool
  * @param numThreads: the number of threads in the pool
  * @return: a thread pool object
 */
ThreadPool::ThreadPool(size_t numThreads) {
  MAX_THREADS = numThreads;
  pthread_mutex_init(&queueMutex, NULL);
  pthread_cond_init(&condition, NULL);
  pthread_mutex_init(&actThreadsMutex, NULL);
  pthread_mutex_init(&workerPingMutex, NULL);
  for (size_t i = 0; i < numThreads; i++) {
    pthread_t thread;
    pthread_create(&thread, NULL, worker, this);
    workers.push_back(thread);
  }
}

/*
  * Destructor for the thread pool
  * @return: void
 */
ThreadPool::~ThreadPool() {
  pool->shutdown = true;
  pthread_cond_broadcast(&condition);
  for (size_t i = 0; i < pool->MAX_THREADS; ++i) {
    pthread_detach(pool->workers[i]);
  }
  pthread_mutex_destroy(&(pool->queueMutex));
  pthread_cond_destroy(&(pool->condition));
}

/*
  * Function to add a task to the thread pool
  * @param task: the task to be added
  * @return: void
 */
void ThreadPool::enqueue(std::function<void()> task) {
  pthread_mutex_lock(&queueMutex);
  tasks.push(std::move(task));
  pthread_mutex_unlock(&queueMutex);
  pthread_cond_signal(&condition);
}

/*
  * Function to create a worker thread
  * @param arg: the thread pool object
  * @return: NULL
 */
void* ThreadPool::worker(void* arg) {
  static_cast<ThreadPool*>(arg)->run();
  return NULL;
}

/*
  * Function to run the worker thread
  * @return: NULL
 */
void* ThreadPool::run() {
  while (true) {
    std::function<void()> task;
    pthread_mutex_lock(&queueMutex);
    while (tasks.empty() && !shutdown) {
      pthread_cond_wait(&condition, &queueMutex);
    }
    if (tasks.empty() && shutdown) {
      pthread_mutex_unlock(&queueMutex);
      break;
    }
    task = std::move(tasks.front());
    tasks.pop();
    pthread_mutex_unlock(&queueMutex);
    task();
  }
  pthread_exit(NULL);
  return NULL;
}

/*
  * Function to open a connection
  * @param fd: the file descriptor of the connection
  * @param buf: the buffer for the connection
  * @return: void
 */
void ThreadPool::openConnection(int fd, char* buf) {
  pthread_mutex_lock(&actThreadsMutex);
  activeConnections[fd] = buf;
  pthread_mutex_unlock(&actThreadsMutex);
}

/*
  * Function to close a connection
  * @param fd: the file descriptor of the connection
  * @return: void
 */
void ThreadPool::closeConnection(int fd) {
  close(fd);
  free(activeConnections[fd]);
  if (verbose) {
    printf("Closing connection %d\n", fd);
    printf("Freed buffer for connection %d\n", fd);
  }
  // if the fd is for worker connection, remove the worker from the system
  if (primary2Fds.find(fds2Primary[fd]) != primary2Fds.end()) {
    pthread_mutex_lock(&workerPingMutex);
    workerLastPing.erase(fds2Primary[fd]);
    pthread_mutex_unlock(&workerPingMutex);
    removeWorker(fds2Primary[fd]);
  } else if (secondary2Fds.find(fds2Secondary[fd]) != secondary2Fds.end()) {
    pthread_mutex_lock(&workerPingMutex);
    workerLastPing.erase(fds2Secondary[fd]);
    pthread_mutex_unlock(&workerPingMutex);
    removeWorker(fds2Secondary[fd]);
  }
  pthread_mutex_lock(&actThreadsMutex);
  activeConnections.erase(fd);
  pthread_mutex_unlock(&actThreadsMutex);
}

/*
  * Function to check if the thread pool is full
  * @return: true if the thread pool is full, false otherwise
 */
bool ThreadPool::isFull() {
  pthread_mutex_lock(&actThreadsMutex);
  bool res = activeConnections.size() >= MAX_THREADS;
  pthread_mutex_unlock(&actThreadsMutex);
  return res;
}

/*
  * Function to check if the thread pool is shutdown
  * @return: true if the thread pool is shutdown, false otherwise
 */
bool ThreadPool::isShutdown() {
  return shutdown;
}

/*
  * Function to handle the ping message (heartbeat) from the worker
  * @param fd: the file descriptor of the connection
  * @param msg: the backend message
  * @return: void
 */
void handlePingMsg(int fd, backendMessage msg) {
  std::string workerId = msg.msgId;
  backendMessage::PingMsg pingMsg = msg.getPingMsg();
  if (workerStatus.find(workerId) == workerStatus.end()) { // register new worker
    std::string workerRole = "unassigned";
    int groupId = -1;
    // if already has an assigned key range, don't assign key range again
    if (pingMsg.hasKeyRange == 'T') {
      std::pair <char, char> letterKeyRange = std::make_pair(pingMsg.letterKeyRange.first, pingMsg.letterKeyRange.second);
      std::pair <char, char> numKeyRange = std::make_pair(pingMsg.numKeyRange.first, pingMsg.numKeyRange.second);
      if (verbose) {
        printf("Register previous existed worker %s with key range: %c-%c, %c-%c\n", workerId.c_str(),
               letterKeyRange.first, letterKeyRange.second - 1, numKeyRange.first, numKeyRange.second - 1);
      }
      for (auto it = groupKeys.begin(); it != groupKeys.end(); ++it) {
        if (it->second.first.first == letterKeyRange.first && it->second.first.second == letterKeyRange.second &&
            it->second.second.first == numKeyRange.first && it->second.second.second == numKeyRange.second) {
          groupId = it->first;
          break;
        }
      }
      if (groupWorkers.find(groupId) == groupWorkers.end() || groupWorkers[groupId].first == "") {
        workerRole = "primary";
      } else {
        workerRole = "secondary";
      }
    } else { // assign key range to the new worker in the system
      bool registered = false;
      for (auto it = groupKeys.begin(); it != groupKeys.end(); ++it) {
        if (groupWorkers.find(it->first) == groupWorkers.end()) {
          workerRole = "primary";
          groupId = it->first;
          registered = true;
          break;
        }
      }
      // if all groups already have a primary, register current workers as a secondary
      if (!registered) {
        auto it = std::min_element(groupSize.begin(), groupSize.end(),
                                  [](const auto& a, const auto& b) {
                                  return a.second < b.second;
                                });
        groupId = it->first;
        workerRole = "secondary";
      }
      if (verbose) {
        printf("Register new worker %s with key range: %c-%c, %c-%c\n", workerId.c_str(),
                groupKeys[groupId].first.first, groupKeys[groupId].first.second - 1,
                groupKeys[groupId].second.first, groupKeys[groupId].second.second - 1);
      }
    }

    if (groupId == -1) {
      fprintf(stderr, "Error: Invalid group id for worker %s\n", workerId.c_str());
      fprintf(stderr, "Please check if the worker has a local key range file for a different group number");
      return;
    }

    // get the number of active secondaries in the group
    int numSecondariesReady = 0;
    std::vector<std::string> secondaries = groupWorkers[groupId].second;
    for (auto it = secondaries.begin(); it != secondaries.end(); ++it) {
      if (workerStatus[*it].first == "Active") {
        numSecondariesReady++;
      }
    }

    // send out the assign message to the worker
    if (workerRole == "primary") {
      groupWorkers[groupId].first = workerId;
      groupWorkers[groupId].second = std::vector<std::string>();
      workerStatus[workerId] = std::make_pair("Recovery", groupId);
      primary2Fds[workerId] = fd;
      fds2Primary[fd] = workerId;
      groupSize[groupId]++;
      // send the assignment to worker
      backendMessage msg = backendMessage(backendMessage::Assign, "", 1);
      msg.setAssignMsg("primary", workerId, secondaries,
                        groupKeys[groupId].first, groupKeys[groupId].second,
                        numSecondariesReady);
      std::vector<char> buffer;
      msg.serialize(buffer);
      write(fd, buffer.data(), buffer.size());
    } else if (workerRole == "secondary") {
      workerStatus[workerId] = std::make_pair("Recovery", groupId);
      secondary2Fds[workerId] = fd;
      fds2Secondary[fd] = workerId;
      groupSize[groupId]++;
      // send assignment to worker
      backendMessage msg = backendMessage(backendMessage::Assign, "", 1);
      msg.setAssignMsg("secondary", groupWorkers[groupId].first, secondaries,
                        groupKeys[groupId].first, groupKeys[groupId].second,
                        numSecondariesReady);
      std::vector<char> buffer;
      msg.serialize(buffer);
      write(fd, buffer.data(), buffer.size());
    } else {
      fprintf(stderr, "Error when assign roles to worker %s\n", workerId.c_str());
    }
  }
  pthread_mutex_lock(&workerPingMutex);
  workerLastPing[workerId] = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  pthread_mutex_unlock(&workerPingMutex);
}

/*
  * Function to handle the request message from the client
  * @param fd: the file descriptor of the connection
  * @param msg: the backend message
  * @return: void
 */
void handleReqMsg(int fd, backendMessage msg) {
  backendMessage::ReqMsg reqMsg = msg.getReqMsg();
  std::string rowName = computeDigest(reqMsg.rowName);
  std::transform(rowName.begin(), rowName.end(), rowName.begin(), ::tolower);
  int groupId = -1;
  for (auto it = groupKeys.begin(); it !=groupKeys.end(); ++it) {
    std::pair<char, char> letterKeyRange = it->second.first;
    std::pair<char, char> numKeyRange = it->second.second;
    if ((rowName[0] >= letterKeyRange.first && rowName[0] < letterKeyRange.second) ||
        (rowName[0] >= numKeyRange.first && rowName[0] < numKeyRange.second)) {
      groupId = it->first;
      break;
    }
  }
  // row key greater than largest key or less than smallest key
  // send request to workers in the first group
  if (groupId == -1) { 
    groupId = groupKeys.end()->first;
  } 
  std::string primaryId = groupWorkers[groupId].first;
  if (groupSize[groupId] == 0 || workerStatus[primaryId].first == "Recovery" || groupWorkers[groupId].first == "") {
    backendMessage msg = backendMessage(backendMessage::Rsp, "", 1);
    msg.setRspMsg(backendMessage::responseType::ERR, "No worker is currently available, try again later...");
    msg.printMsg();
    std::vector<char> buffer;
    msg.serialize(buffer);
    int writeBytes = write(fd, buffer.data(), buffer.size());
    if (writeBytes < 0) {
      fprintf(stderr, "Error: Failed to write to socket: %s\n", strerror(errno));
    }
    if (verbose) {
      printf("No worker is currently available\n");
    }
    return;
  }
  // send the redirect address to client
  if (groupLastReq.find(groupId) == groupLastReq.end()) {
    groupLastReq[groupId] = 0;
  } else {
    groupLastReq[groupId] = (groupLastReq[groupId] + 1) % (groupWorkers[groupId].second.size() + 1);
  }
  if (groupLastReq[groupId] == 0) {
    // redirect the request to the primary
    std::string primaryId = groupWorkers[groupId].first;
    backendMessage msg = backendMessage(backendMessage::Redir, "", 1);
    msg.setRedirMsg(primaryId);
    std::vector<char> buffer;
    msg.serialize(buffer);
    write(fd, buffer.data(), buffer.size());
    if (verbose) {
      printf("Received request %d from client for row %s\n", reqMsg.reqType, rowName.c_str());
      printf("Redirecting request to primary worker %s\n", primaryId.c_str());
    }
  } else {
    // redirect the request to the secondary
    std::string secondaryId = groupWorkers[groupId].second[groupLastReq[groupId] - 1];
    backendMessage msg = backendMessage(backendMessage::Redir, "", 1);
    msg.setRedirMsg(secondaryId);
    std::vector<char> buffer;
    msg.serialize(buffer);
    write(fd, buffer.data(), buffer.size());
    if (verbose) {
      printf("Received request %d from client for row %s\n", reqMsg.reqType, rowName.c_str());
      printf("Redirecting request to secondary worker %s\n", secondaryId.c_str());
    }
  }
}

/*
  * Function to handle the an incoming connection
  * @param fd: the file descriptor of the connection
  * @param buf: the buffer for the connection
  * @return: void
 */
void handleConnection(int fd, char* buf) {
  int rcvd = 0;
  int dataLeft = 0;
  uint32_t msgSize;

  while (rcvd < BUFFER_SIZE) {
    int n = read(fd, buf + rcvd, BUFFER_SIZE - rcvd);
    // if (verbose) {
      // printf("Received %d bytes\n", n);
    // }
    if (n < 0) {
      fprintf(stderr, "Error: Failed to read from socket: %s\n", strerror(errno));
      break;
    } else if (n == 0) {
      break;
    }
    rcvd += n;

    while (rcvd > 0) {
      backendMessage msg = backendMessage();
      if (!msg.deserialize(buf, rcvd)) {
        break;
      }
      if (msg.msgType == backendMessage::Ping) {
        handlePingMsg(fd, msg);
      } else if (msg.msgType == backendMessage::Req || msg.msgType == backendMessage::Append) {
        handleReqMsg(fd, msg);
      } else if (msg.msgType == backendMessage::RecoveryDone) {
        std::string recoveredWorkerId = msg.getRecoveryDoneMsg().workerId;
        if (verbose) {
          printf("Worker %s is ready to work\n", recoveredWorkerId.c_str());
        }
        workerStatus[recoveredWorkerId].first = "Active";

        // let the group primary knows that a new secondary worker worker is ready to work
        if (primary2Fds.find(recoveredWorkerId) == primary2Fds.end()) {
          int groupId = workerStatus[recoveredWorkerId].second;
          std::string groupPrimary = groupWorkers[groupId].first;
          // if the original primary dead, assign current worker to be the new primary
          if (groupPrimary == "") {
            groupWorkers[groupId].first = recoveredWorkerId;
            primary2Fds[recoveredWorkerId] = fd;
            fds2Primary[fd] = recoveredWorkerId;
            secondary2Fds.erase(recoveredWorkerId);
            fds2Secondary.erase(fd);
          } else if (primary2Fds.find(recoveredWorkerId) == primary2Fds.end()) {
            // else, add the worker to be secondary group
            groupWorkers[groupId].second.push_back(recoveredWorkerId);
          }

          // send the new group information to the primary
          std::vector<std::string> groupSecondaries = groupWorkers[groupId].second;
          int numSecondariesReady = 0;
          for (auto it = groupSecondaries.begin(); it != groupSecondaries.end(); ++it) {
            if (workerStatus[*it].first == "Active") {
              numSecondariesReady++;
            }
          }
          backendMessage assignMsg = backendMessage(backendMessage::Assign, "", 1);
          assignMsg.setAssignMsg("primary", groupPrimary, groupSecondaries,
                                groupKeys[groupId].first, groupKeys[groupId].second,
                                numSecondariesReady);
          std::vector<char> buffer;
          assignMsg.serialize(buffer);
          int writeBytes = write(primary2Fds[groupPrimary], buffer.data(), buffer.size());
          if (writeBytes < 0) {
            fprintf(stderr, "Error: Failed to write to socket: %s\n", strerror(errno));
          }
          printf("Sent assignment message with new secondary to primary worker %s\n", groupPrimary.c_str());
        }
      } else if (msg.msgType == backendMessage::CP) {
        std::string workerId;
        if (primary2Fds.find(fds2Primary[fd]) != primary2Fds.end()) {
          workerId = fds2Primary[fd];
        } else if (secondary2Fds.find(fds2Secondary[fd]) != secondary2Fds.end()) {
          workerId = fds2Secondary[fd];
        } else {
          fprintf(stderr, "Error: Invalid worker id for checkpointing\n");
          break;
        }
        int groupId = workerStatus[workerId].second;
        std::string groupPrimary = groupWorkers[groupId].first;
        bool inRecovery = false;
        while (true) { // busy wait for all recovering workers to finish
          for (auto it2 = workerStatus.begin(); it2 != workerStatus.end(); ++it2) {
            if (it2->second.first == "Recovery" && it2->second.second == groupId) {
              inRecovery = true;
              break;
            }
          }
          if (!inRecovery) {
            backendMessage msg = backendMessage(backendMessage::CP, "", 1);
            msg.setCPMsg(1);
            std::vector<char> buffer;
            msg.serialize(buffer);
            if (write(fd, buffer.data(), buffer.size()) < 0) {
              fprintf(stderr, "Error: Failed to write to socket for CP message: %s\n", strerror(errno));
            }
            lastCP = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            if (verbose) {
              printf("Sent checkpointing message to group %d: primary worker %s\n", groupId, groupPrimary.c_str());
            }
            break;
          }
        }
      } else if (msg.msgType == backendMessage::GetInfoReq) {
        backendMessage rsp = backendMessage(backendMessage::GetInfoRsp, "", 1);
        std::map<std::string, std::string> serverInfo;
        for (auto it = workerStatus.begin(); it != workerStatus.end(); ++it) {
          serverInfo[it->first] = it->second.first;
        }
        rsp.setGetInfoRspMsg(serverInfo);
        std::vector<char> buffer;
        rsp.serialize(buffer);
        write(fd, buffer.data(), buffer.size());
      } else {
        fprintf(stderr, "Error: Invalid message type %d sent to coordinator\n", msg.msgType);
      }
      msgSize = msg.getSerializedSize();
      dataLeft = rcvd - msgSize;
      memmove(buf, buf + msgSize, dataLeft);
      memset(buf + dataLeft, 0, BUFFER_SIZE - dataLeft);
      rcvd = dataLeft;
    }
  }
  pool->closeConnection(fd);
}

/*
  * Function to initialize a checkpointing once in a while
  * @param arg: the argument for the thread
  * @return: NULL
 */
void* checkPointInit(void* arg) {
  struct timespec ts;
  ts.tv_sec = CHECKPOINT_INTERVAL;
  ts.tv_nsec = 0;
  backendMessage msg = backendMessage(backendMessage::CP, "", 1);
  msg.setCPMsg(0);
  std::vector<char> buffer;
  msg.serialize(buffer);

  while (true) {
    nanosleep(&ts, NULL);
    if (std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()) - lastCP < CHECKPOINT_INTERVAL) {
      continue;
    }
    if (verbose) {
      printf("Initialize checkpointing...\n");
    }
    for (auto it = primary2Fds.begin(); it != primary2Fds.end(); ++it) {
      // if any of the worker in the group is in recovery, do not checkpoint
      bool inRecovery = false;
      int groupId = workerStatus[it->first].second;
      for (auto it2 = workerStatus.begin(); it2 != workerStatus.end(); ++it2) {
        if (it2->second.first == "Recovery" && it2->second.second == groupId) {
          inRecovery = true;
          break;
        }
      }
      if (!inRecovery) {
        write(it->second, buffer.data(), buffer.size());
        lastCP = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
      }
    }
  }
  return NULL;
}

/*
  * Function to audit the workers' heartbeats
  * @param arg: the argument for the thread
  * @return: NULL
 */
void* auditWorker(void* arg) {
  struct timespec ts;
  ts.tv_sec = AUDIT_WORKER_INTERVAL;
  ts.tv_nsec = 0;
  while (true) {
    nanosleep(&ts, NULL);
    // if (verbose) {
    //   printf("Auditing workers...\n");
    // }
    for (auto it = workerLastPing.begin(); it != workerLastPing.end();) {
      time_t currTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
      pthread_mutex_lock(&workerPingMutex);
      if (currTime - it->second > WORKER_TIMEOUT) { // worker dead
        pthread_mutex_unlock(&workerPingMutex);
        if (verbose) {
          printf("Detected inactive worker: %s\n", it->first.c_str());
        }
        removeWorker(it->first);
        pthread_mutex_lock(&workerPingMutex);
        it = workerLastPing.erase(it);
        pthread_mutex_unlock(&workerPingMutex);
      } else {
        pthread_mutex_unlock(&workerPingMutex);
        ++it;
      }
    }
  }
}

/*
  * Function to remove an inactive worker from the system
  * @param workerId: the id of the worker to be removed
  * @return: void
 */
void removeWorker(std::string workerId) {
  if (verbose) {
    printf("Removing worker %s\n", workerId.c_str());
  }
  int groupNum = workerStatus[workerId].second;
  groupSize[groupNum]--;
  if (primary2Fds.find(workerId) != primary2Fds.end()) { // worker is primary
    fds2Primary.erase(primary2Fds[workerId]);
    primary2Fds.erase(workerId);
    // no worker is available for the new primary
    if (groupWorkers[groupNum].second.size() == 0) {
      groupWorkers[groupNum].first = "";
    } else {
      // assign new primary
      groupWorkers[groupNum].first = groupWorkers[groupNum].second[0];
      groupWorkers[groupNum].second.erase(groupWorkers[groupNum].second.begin());
      int newPrimaryFd = secondary2Fds[groupWorkers[groupNum].first];
      primary2Fds[groupWorkers[groupNum].first] = newPrimaryFd;
      fds2Primary[newPrimaryFd] = groupWorkers[groupNum].first;
      fds2Secondary.erase(newPrimaryFd);
      secondary2Fds.erase(groupWorkers[groupNum].first);

      // send the new group information to the new primary
      std::vector<std::string> groupSecondaries = groupWorkers[groupNum].second;
      int numSecondariesReady = 0;
      for (auto it2 = groupSecondaries.begin(); it2 != groupSecondaries.end(); ++it2) {
        if (workerStatus[*it2].first == "Active") {
          numSecondariesReady++;
        }
      }
      backendMessage msg = backendMessage(backendMessage::Assign, "", 1);
      msg.setAssignMsg("primary", groupWorkers[groupNum].first, groupSecondaries,
                        groupKeys[groupNum].first, groupKeys[groupNum].second,
                        numSecondariesReady);
      std::vector<char> buffer;
      msg.serialize(buffer);
      write(primary2Fds[groupWorkers[groupNum].first], buffer.data(), buffer.size());

      // send the new group information to the secondaries
      backendMessage msg2 = backendMessage(backendMessage::Assign, "", 1);
      msg2.setAssignMsg("secondary", groupWorkers[groupNum].first, groupSecondaries,
                        groupKeys[groupNum].first, groupKeys[groupNum].second,
                        numSecondariesReady);
      std::vector<char> buffer2;
      msg2.serialize(buffer2);
      for (auto it2 = groupWorkers[groupNum].second.begin(); it2 != groupWorkers[groupNum].second.end(); ++it2) {
        write(secondary2Fds[*it2], buffer2.data(), buffer2.size());
      }
    }
  } else if (secondary2Fds.find(workerId) != secondary2Fds.end()) { // worker is secondary
    fds2Secondary.erase(secondary2Fds[workerId]);
    secondary2Fds.erase(workerId);
    std::string groupPrimary = groupWorkers[groupNum].first;
    // remove the dead worker from the group
    for (auto it2 = groupWorkers[groupNum].second.begin(); it2 != groupWorkers[groupNum].second.end(); ++it2) {
      if (*it2 == workerId) {
        groupWorkers[groupNum].second.erase(it2);
        break;
      }
    }
    // if the primary still alive, send the new group information to the primary
    if (groupPrimary != "") {
      std::vector<std::string> groupSecondaries = groupWorkers[groupNum].second;
      int numSecondariesReady = 0;
      for (auto it2 = groupSecondaries.begin(); it2 != groupSecondaries.end(); ++it2) {
        if (workerStatus[*it2].first == "Active") {
          numSecondariesReady++;
        }
      }
      backendMessage msg = backendMessage(backendMessage::Assign, "", 1);
      msg.setAssignMsg("primary", groupPrimary, groupSecondaries,
                        groupKeys[groupNum].first, groupKeys[groupNum].second,
                        numSecondariesReady);
      std::vector<char> buffer;
      msg.serialize(buffer);
      int bytesWrite = write(primary2Fds[groupPrimary], buffer.data(), buffer.size());
      if (bytesWrite < 0) {
        fprintf(stderr, "Error: Failed to write to socket: %s\n", strerror(errno));
      }
    }
  } else {
    fprintf(stderr, "Error: Worker %s is not found\n", workerId.c_str());
  }

  workerStatus.erase(workerId);
  if (verbose) {
    printf("Worker %s is removed\n", workerId.c_str());
    printf("Group %d size: %d\n", groupNum, groupSize[groupNum]);
    printf("Registered worker size: %ld\n", workerLastPing.size());
  }
}

/*
  * Function to handle the SIGINT signal
  * @param signum: the signal number
  * @return: NULL
 */
void sigIntHandler(int signum) {
  pthread_mutex_lock(&actThreadsMutex);
  for (std::map<int, char*>::iterator iter = activeConnections.begin(); iter != activeConnections.end(); iter++) {
    if (iter->second != nullptr) {
      free(iter->second);
      iter->second = nullptr;
    }
    close(iter->first);
  }
  activeConnections.clear();
  pthread_mutex_unlock(&actThreadsMutex);
  pthread_mutex_destroy(&actThreadsMutex); 
  pthread_mutex_destroy(&workerPingMutex);
  delete pool;
  pool = nullptr;
  pthread_detach(checkpointThread);
  pthread_detach(auditWorkerThread);
  exit(0);
}


int main(int argc, char* argv[]) {
  if (argc < 2) {
      fprintf(stderr, "need to provide IP and port number\n");
      exit(1);
  }

  int cOpt;
  int numGroups = 3;
  std::signal(SIGINT, sigIntHandler);

  // parse the command line options
  while ((cOpt = getopt(argc, argv, "vg:")) != -1) {
    switch (cOpt) {
    case 'v':
      verbose = true;
      break;
    case 'g':
      if (optarg == NULL || !isdigit(*optarg)) {
        fprintf(stderr, "Error: Invalid number of groups\n");
        exit(127);
      }
      numGroups = atoi(optarg);
      break;
    default:
      fprintf(stderr, "Error: Invalid option parameter\n");
      exit(127);
    }
  }

  if (optind == argc) {
    fprintf(stderr, "Error: Missing IP and Port\n");
    exit(127);
  }

  // create key range based on the number of groups
  // possible key characters for md5hash: 'a-z0-9'
  int letterKeysNum = 26 / numGroups;
  int extraLetterKeys = 26 % numGroups;
  int numKeyNum = 10 / numGroups;
  int extraNumKeys = 10 % numGroups;
  int letterKey = 0;
  int numKey = 0;
  for (int i = 0; i < numGroups; ++i) {
    int letterGroupSize = letterKeysNum + (i < extraLetterKeys ? 1 : 0);
    int numGroupSize = numKeyNum + ((numGroups - i) <= extraNumKeys ? 1 : 0);
    char startLetterKey = 'a' + letterKey;
    letterKey += letterGroupSize;
    char endLetterKeyExclusive = 'a' + letterKey;
    char startNumKey = '0' + numKey;
    numKey += numGroupSize;
    char endNumKeyExclusive = '0' + numKey;
    std::pair<char, char> letterKeyPair = std::make_pair(startLetterKey, endLetterKeyExclusive);
    std::pair<char, char> numKeyPair = std::make_pair(startNumKey, endNumKeyExclusive);
    groupKeys[i] = std::make_pair(letterKeyPair, numKeyPair);
  }

  if (verbose) {
    printf("Number of groups: %d\n", numGroups);
    for (auto it = groupKeys.begin(); it != groupKeys.end(); ++it) {
      printf("Group %d: letter key range: %c-%c, number key range: %c-%c\n", it->first,
             it->second.first.first, it->second.first.second - 1, it->second.second.first, it->second.second.second - 1);
    }
  }

  // parse IP and Port
  std::string address = argv[optind];
  int pos = address.find(':');
  if (pos == std::string::npos) {
    fprintf(stderr, "Error: Invalid IP and Port\n");
    exit(127);
  }
  std::string ip = address.substr(0, pos);
  if (ip == "localhost") {
      ip = "127.0.0.1";
  }
  int port = std::stoi(address.substr(pos + 1));

  // create a socket
  int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0) {
    fprintf(stderr, "Error: Failed to create socket: %s\n", strerror(errno));
    exit(1);
  }

  struct sockaddr_in servaddr;
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htons(INADDR_ANY);
  servaddr.sin_port = htons(port);
  if (verbose) {
    printf("Backend Coordinator Listening on port %d\n", port);
  } 

  int opt = 1;
  int setSockOptSuccess = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, &opt, sizeof(opt));
  if (setSockOptSuccess < 0) {
    fprintf(stderr, "Error: Failed to set socket options: %s\n", strerror(errno));
    exit(1);
  }
  int bindSuccess = bind(listen_fd, (struct sockaddr*)&servaddr, sizeof(servaddr));
  if (bindSuccess < 0) {
    fprintf(stderr, "Error: Failed to bind to port %d: %s\n", port, strerror(errno));
    exit(1);
  }
  int listenSuccess = listen(listen_fd, NUM_CONNECTIONS);
  if (listenSuccess < 0) {
    fprintf(stderr, "Error: Failed to listen on port %d: %s\n", port, strerror(errno));
    exit(1);
  }

  // create a thread for periodically checkpointing
  pthread_create(&checkpointThread, NULL, checkPointInit, NULL);

  // create a thread for auditing workers
  pthread_create(&auditWorkerThread, NULL, auditWorker, NULL);

  // create a thread pool
  pool = new ThreadPool(NUM_CONNECTIONS);

  while (true){
    struct sockaddr_in clientaddr;
    socklen_t clientaddrlen = sizeof(clientaddr);

    // check if the thread pool is full, if so, send a message and close the connection
    if (pool->isFull()) continue;

    int fd = accept(listen_fd, (struct sockaddr*)&clientaddr, &clientaddrlen);
    if (fd < 0) {
      fprintf(stderr, "Error: Failed to accept connection: %s\n", strerror(errno));
      continue;
    }

    if (pool->isFull()) {
      backendMessage msg = backendMessage(backendMessage::Rsp, "", 1);
      msg.setRspMsg(backendMessage::responseType::ERR, "Server is busy, try again later...");
      std::vector<char> buffer;
      msg.serialize(buffer);
      write(fd, buffer.data(), buffer.size());
      close(fd);
      continue;
    }

    if (pool->isShutdown()) {
      backendMessage msg = backendMessage(backendMessage::Rsp, "", 1); 
      msg.setRspMsg(backendMessage::responseType::SHUTDOWN, "Server is shutting down...");
      std::vector<char> buffer;
      msg.serialize(buffer);
      close(fd);
      break;
    }
    
    if (verbose) {
      printf("[%d] New connection from %s\n", fd, inet_ntoa(clientaddr.sin_addr));
    }

    // accept the connection and send the greeting message if the thread pool is not full
    char* buf = (char*)malloc(BUFFER_SIZE);
    if (buf == NULL) {
      fprintf(stderr, "Error: Failed to allocate memory for buffer\n");
      close(fd);
    }
    memset(buf, 0, BUFFER_SIZE);

    pool->openConnection(fd, buf);
    pool->enqueue([fd, buf] {
      handleConnection(fd, buf);
    });
  }

  close(listen_fd);
  pthread_detach(checkpointThread);
  pthread_detach(auditWorkerThread);
  delete pool;
  pool = nullptr;

  return 0;

}
