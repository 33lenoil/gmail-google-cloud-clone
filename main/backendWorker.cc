#include "backendWorker.h"

#define BUFFERLENGTH 10000
#define PINGINTERVAL 5
#define MAXQUEUED 100
#define CONTENTLENGTH 9000
#define MEMLIMIT 2e+9

std::string computeDigest(std::string input)
{
	unsigned char digestBuffer[MD5_DIGEST_LENGTH];
	const char *data = input.c_str();
	MD5_CTX c;
	MD5_Init(&c);
	MD5_Update(&c, (const unsigned char *)data, input.length());
	MD5_Final(digestBuffer, &c);

	// hex string conversion
	std::string result;
	for (std::size_t i = 0; i != 16; i++)
	{
		result += "0123456789ABCDEF"[digestBuffer[i] / 16];
		result += "0123456789ABCDEF"[digestBuffer[i] % 16];
	}
	return result;
}

int main(int argc, char *argv[])
{
	// three args: own ip:port, coordinator ip:port, folder path
	// optional arg: -v
	if (argc < 4)
	{
		std::cerr << "-ERR Not enough arguments\n";
		exit(1);
	}

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigHandler;
	sigaction(SIGINT, &sa, NULL);

	// parse the IP and port of the server
	std::string ownIpPort = argv[1];
	size_t ownColonIndex = ownIpPort.find(":");
	if (ownColonIndex == std::string::npos)
	{
		std::cerr << "Error: no colon in argument\n";
		exit(1);
	}

	// get the IP address and the port of the server
	ownIp = ownIpPort.substr(0, ownColonIndex);
	ownPort = std::stoi(
		ownIpPort.substr(ownColonIndex + 1, ownIpPort.length()));

	// parse the IP and port of the coordinator
	std::string coordIpPort = argv[2];
	size_t coordColonIndex = coordIpPort.find(":");
	if (coordColonIndex == std::string::npos)
	{
		std::cerr << "Error: no colon in argument\n";
		exit(1);
	}

	// get the IP address and the port of the coordinator
	coordIp = coordIpPort.substr(0, coordColonIndex);
	coordPort = std::stoi(
		coordIpPort.substr(coordColonIndex + 1, coordIpPort.length()));

	// get the path of the files folder
	path = argv[3];

	// check the path
	fs::path dirPath = path;
	if (!fs::is_directory(dirPath))
	{
		if (verbose)
		{
			std::cout << "No tables folder, creating one...\n";
		}
		if (mkdir(path.c_str(), 0777) == -1)
		{
			std::cerr << "Error: can't create tables folder\n";
			exit(1);
		}
	}

	std::string userTableName = path + "/" + "UserInfoTable";
	std::string fileTableName = path + "/" + "UserFileTable";
	std::string inboxTableName = path + "/" + "InboxTable";

	// check the UserInfoTable path
	fs::path userTableDirPath = userTableName;
	if (!fs::is_directory(userTableDirPath))
	{
		if (verbose)
		{
			std::cout << "No user info table, creating one...\n";
		}
		if (mkdir(userTableName.c_str(), 0777) == -1)
		{
			std::cerr << "Error: can't create user info table\n";
			exit(1);
		}
	}

	// check the UserFileTable path
	fs::path fileTableDirPath = fileTableName;
	if (!fs::is_directory(fileTableDirPath))
	{
		if (verbose)
		{
			std::cout << "No file info table, creating one...\n";
		}
		if (mkdir(fileTableName.c_str(), 0777) == -1)
		{
			std::cerr << "Error: can't create file info table\n";
			exit(1);
		}
	}

	// check the InboxTable path
	fs::path inboxTableDirPath = inboxTableName;
	if (!fs::is_directory(inboxTableDirPath))
	{
		if (verbose)
		{
			std::cout << "No inbox table, creating one...\n";
		}
		if (mkdir(inboxTableName.c_str(), 0777) == -1)
		{
			std::cerr << "Error: can't create inbox table\n";
			exit(1);
		}
	}

	// get verbose
	if (argc == 5)
	{
		std::string flag = argv[4];
		if (flag.compare("-v") == 0)
			verbose = true;
	}

	for (int i = 0; i < NUMTHREADS; i++)
	{
		args[i] = (struct threadArgs *)malloc(sizeof(struct threadArgs));
	}

	// init the locks
	pthread_mutex_init(&userOffsetLock, NULL);
	pthread_mutex_init(&fileOffsetLock, NULL);
	pthread_mutex_init(&queueLock, NULL);
	pthread_mutex_init(&outQueueLock, NULL);

	while (true)
	{
		// check if pretending death
		while (pretend)
		{
		}
		printf("After pretend, pretned value: %d\n", pretend);

		// create the server's own socket
		ownSocket = socket(PF_INET, SOCK_STREAM, 0);
		if (ownSocket < 0)
		{
			if (verbose)
				std::cerr << "Cannot open own socket because: " << strerror(errno)
						  << "\n";
			exit(1);
		}

		// bind the socket and start listening
		struct sockaddr_in ownAddr;
		bzero(&ownAddr, sizeof(ownAddr));
		ownAddr.sin_family = AF_INET;
		ownAddr.sin_addr.s_addr = inet_addr(ownIp.c_str());
		ownAddr.sin_port = htons(ownPort);

		int opt = 1;
		setsockopt(ownSocket, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt,
				   sizeof(opt));

		int res = bind(ownSocket, (struct sockaddr *)&ownAddr, sizeof(ownAddr));
		if (res < 0)
		{
			if (verbose)
				std::cerr << "Cannot bind socket (" << strerror(errno) << ")\n";
			close(ownSocket);
			exit(1);
		}

		// the coordinator socket
		coordSocket = socket(PF_INET, SOCK_STREAM, 0);
		if (coordSocket < 0)
		{
			if (verbose)
				std::cerr << "Cannot open coordinator socket because: "
						  << strerror(errno) << "\n";
			exit(1);
		}

		struct sockaddr_in coordAddr;
		bzero(&coordAddr, sizeof(coordAddr));
		coordAddr.sin_family = AF_INET;
		coordAddr.sin_addr.s_addr = inet_addr(coordIp.c_str());
		coordAddr.sin_port = htons(coordPort);
		connect(coordSocket, (struct sockaddr *)&coordAddr, sizeof(coordAddr));

		// create a thread that keeps pinging the coordinator
		pthread_create(&pingThread, NULL, pingWorker, NULL);

		// create a thread that reads from the coordinator
		pthread_create(&coordThread, NULL, coordWorker, NULL);

		if (listen(ownSocket, MAXQUEUED) < 0)
		{
			if (verbose)
				std::cerr << "Cannot listen on socket (" << strerror(errno)
						  << ")\n";
			close(ownSocket);
			exit(1);
		};

		// initialize the lock
		pthread_mutex_init(&logFileMutex, NULL);
		pthread_mutex_init(&cpMutex, NULL);

		// accept requests and create threads
		while (!shuttingDown)
		{
			if (verbose)
				std::cerr << "listen loop\n";
			struct sockaddr_in clientaddr;
			socklen_t clientaddrlen = sizeof(clientaddr);

			// check if there are free spots
			pthread_mutex_lock(&lock);
			if (fdCount >= NUMTHREADS)
			{
				pthread_mutex_unlock(&lock);
				continue;
			}

			if (verbose)
				std::cerr << "find a spot\n";
			// find a spot
			int index = 0;
			while (fds[index] != 0)
				index++;
			if (verbose)
				std::cerr << "found index: " << index << "\n";
			pthread_mutex_unlock(&lock);

			if (verbose)
				std::cerr << "Ready to create fd\n";
			// accept the incoming connection
			int *fd = (int *)malloc(sizeof(int));
			if (verbose)
				std::cerr << "Fd malloced\n";
			*fd = accept(ownSocket, (struct sockaddr *)&clientaddr, &clientaddrlen);
			if (verbose)
			{
				std::cout << "fd accepted: " << *fd << std::endl;
			}
			if (pretend)
			{
				printf("Pretend2: %d\n", pretend);
				free(fd);
				break;
			}
			if (verbose)
				std::cerr << "Fd: " << *fd << "\n";
			if (*fd < 0)
			{
				if (verbose && !shuttingDown)
					std::cerr << "Cannot accept connection (" << strerror(errno)
							  << ")\n";
				continue;
			}
			if (verbose)
				std::cerr << "Fd accepted\n";
			pthread_mutex_unlock(&lock);
			fds[index] = *fd;
			fdCount++;
			pthread_mutex_unlock(&lock);
			if (verbose)
				std::cerr << "[" << *fd << "]"
						  << " New connection from " << inet_ntoa(clientaddr.sin_addr) << ":" << std::to_string(ntohs(clientaddr.sin_port)) << " \n";

			args[index]->index = index;
			args[index]->fd = *fd;
			pthread_create(&threads[index], NULL, worker, args[index]);
			free(fd);
			fd = NULL;
		}
		if (shuttingDown)
		{
			if (verbose)
			{
				std::cout << "Main loop shutdown" << std::endl;
			}
			break;
		}
	}
	if (verbose)
		std::cerr << "Server shut down\n";
	//	pthread_cancel(pingThread);
	//	pthread_join(pingThread, NULL);
	//	pthread_cancel(coordThread);
	//	pthread_join(coordThread, NULL);
	//	close(ownSocket);
	//	close(coordSocket);

	// wait on the threads to finish
	//	for (pthread_t tid : threads) {
	//		if (tid == 0)
	//			continue;
	//		pthread_cancel(tid);
	//		pthread_join(tid, NULL);
	//	}
	//	pthread_mutex_destroy(&lock);

	//	for (struct threadArgs *arg : args) {
	//		free(arg);
	//	}

	exit(0);
}

/*
 * A function that pings the coordinator every 5 seconds
 */
void ping()
{
	std::vector<char> buffer;
	backendMessage pingMsg = backendMessage(backendMessage::Ping,
											ownIp + ":" + std::to_string(ownPort), 1);
	fs::path keyRangeFile(path + "/keyRange.txt");
	bool existsKeyRange = fs::exists(keyRangeFile);
	if (existsKeyRange && groupRole == "unassigned")
	{
		int fd = open((path + "/keyRange.txt").c_str(), O_RDONLY);
		if (fd < 0)
		{
			fprintf(stderr, "Error: Failed to open keyRange file: %s\n",
					strerror(errno));
			return;
		}
		char range[4];
		std::pair<char, char> letterKeyRange;
		std::pair<char, char> numberKeyRange;
		read(fd, &range, 4);
		letterKeyRange.first = range[0];
		letterKeyRange.second = range[1];
		numberKeyRange.first = range[2];
		numberKeyRange.second = range[3];
		close(fd);
		pingMsg.setPingMsg('T', letterKeyRange, numberKeyRange);
	}
	else
	{
		pingMsg.setPingMsg('F', std::make_pair('0', '0'),
						   std::make_pair('0', '0'));
	}
	pingMsg.serialize(buffer);
	write(coordSocket, buffer.data(), buffer.size());
}

/*
 * The worker function for the thread that pings the coordinator
 * Input: unused, args that are not used
 */
void *pingWorker(void *unused)
{
	struct timespec ts;
	ts.tv_sec = PINGINTERVAL;
	ts.tv_nsec = 0;
	if (verbose)
	{
		printf("Worker %s start ping coordinator\n", (ownIp + ":" + std::to_string(ownPort)).c_str());
	}
	while (true)
	{
		ping();
		nanosleep(&ts, NULL);
	}
}

/*
 * The worker thread that reads the messages sent by the coordinator
 * Input: unused, args that are not used
 */
void *coordWorker(void *unused)
{
	coordBuffer = (char *)malloc(BUFFERLENGTH);
	if (coordBuffer == NULL)
	{
		fprintf(stderr, "Error: Failed to allocate memory for buffer\n");
		pthread_exit(NULL);
	}
	memset(coordBuffer, 0, BUFFERLENGTH);

	if (shuttingDown)
	{
		close(coordSocket);
		pthread_exit(NULL);
		return NULL;
	}

	int rcvd = 0;
	int dataLeft = 0;
	uint32_t msgSize;
	while (true)
	{
		int n = read(coordSocket, coordBuffer + rcvd, BUFFERLENGTH - rcvd);
		if (shuttingDown)
		{
			close(coordSocket);
			pthread_exit(NULL);
			return NULL;
		}
		if (n < 0)
		{
			fprintf(stderr, "Error: Failed to read from socket: %s\n",
					strerror(errno));
			break;
		}
		else if (n == 0)
		{
			if (verbose)
			{
				printf("CoordWorker: Socket closed\n");
			}
			break;
		}
		rcvd += n;

		while (rcvd > 0)
		{
			backendMessage msg = backendMessage();
			if (!msg.deserialize(coordBuffer, rcvd))
			{
				break;
			}
			if (msg.msgType == backendMessage::Assign)
			{
				backendMessage::AssignMsg assignMsg = msg.getAssignMsg();
				parseAssignment(assignMsg);
			}
			else if (msg.msgType == backendMessage::CP)
			{
				if (!isCheckpointing)
				{
					cpVersion++;
					// forward checkpoint request to secondaries
					backendMessage cpMsg = backendMessage(backendMessage::CP,
														  "cp" + std::to_string(cpVersion), 1);
					cpMsg.setCPMsg(cpVersion);
					std::vector<char> buffer;
					cpMsg.serialize(buffer);
					for (std::string ipPort : secondaryIpPorts)
					{
						forwardToPeers(cpMsg, ipPort);
					}

					if (verbose)
					{
						printf("Primary: Received CP request from coordinator for version #%d\n", cpVersion);
					}

					bool cpFinished = false;
					if (doCheckpoint())
					{
						lastCPSuccess = true;
						pthread_mutex_lock(&cpMutex);
						numCPFinished++;
						cpFinished = numCPFinished == secondaryIpPorts.size() + 1;
						pthread_mutex_unlock(&cpMutex);
					}
					if (cpFinished)
					{
						backendMessage cpAckMsg = backendMessage(backendMessage::CPAck, "", 1);
						cpAckMsg.setCPAckMsg(backendMessage::responseType::OK);
						buffer.clear();
						cpAckMsg.serialize(buffer);
						for (std::string ipPort : secondaryIpPorts)
						{
							forwardToPeers(cpAckMsg, ipPort);
						}
						if (verbose)
						{
							printf("Primary: Finished CP for version %d\n", cpVersion);
						}
						clearQueue();
						numCPFinished = 0;
						lastCPSuccess = false;
					}
				}
			}
			else
			{
				fprintf(stderr, "Invalid message type from coordinator: %d\n",
						msg.msgType);
			}
			msgSize = msg.getSerializedSize();
			dataLeft = rcvd - msgSize;
			memmove(coordBuffer, coordBuffer + msgSize, dataLeft);
			memset(coordBuffer + dataLeft, 0, BUFFERLENGTH - dataLeft);
			rcvd = dataLeft;
		}
		if (shuttingDown)
		{
			close(coordSocket);
			pthread_exit(NULL);
			return NULL;
		}
	}
	free(coordBuffer);
	coordBuffer = NULL;
	close(coordSocket);
	pthread_exit(NULL);
}

/*
 * The worker thread that reads the messages sent by clients and other servers
 * Input: arg, the args to the woeker
 */
void *worker(void *arg)
{
	struct threadArgs *args = (struct threadArgs *)arg;
	int commFd = args->fd;
	int index = args->index;

	if (shuttingDown)
	{
		close(commFd);
		fds[index] = 0;
		pthread_exit(NULL);
		return NULL;
	}

	char *buffer = (char *)malloc(BUFFERLENGTH);
	printf("Worker: Malloc buffer, buffer: %p\n", buffer);
	printf("commFd: %d\n", commFd);
	buffers[index] = buffer;
	uint32_t rcvd = 0;
	uint32_t msgSize;
	while (true)
	{
		printf("Worker: Reading from client\n");
		int bytesRead = read(commFd, &buffer[rcvd], BUFFERLENGTH - rcvd);
		printf("Worker: Read %d bytes\n", bytesRead);
		if (bytesRead < 0)
		{
			if (verbose)
			{
				std::cout << "socket error\n";
			}
			break;
		}
		if (bytesRead == 0)
		{
			if (verbose)
			{
				std::cout << "socket closed\n";
			}
			break;
		}
		if (shuttingDown)
		{
			close(commFd);
			pthread_mutex_lock(&lock);
			fds[index] = 0;
			fdCount--;
			free(buffers[index]);
			buffers[index] = NULL;
			pthread_mutex_unlock(&lock);
			pthread_exit(NULL);
			return NULL;
		}

		rcvd += bytesRead;
		printf("Worker: Received %d bytes\n", rcvd);

		while (rcvd > 0)
		{
			backendMessage msg = backendMessage();
			if (!msg.deserialize(buffer, rcvd))
			{
				break;
			}
			printf("Msg at worker loop: \n");
			msg.printMsg();
			printf("Worker: Deserialized message\n");
			if (msg.msgType == backendMessage::CPAck)
			{
				msg.printMsg();
			}

			pthread_mutex_lock(&lock);
			msgIds[index] = msg.msgId;
			msgId2Index[msg.msgId] = index;
			pthread_mutex_unlock(&lock);

			// log the request from clients
			off_t offset = 0;
			if (msg.msgType == backendMessage::messageType::Req && (msg.getReqMsg().reqType == backendMessage::requestType::PUT ||
																	msg.getReqMsg().reqType == backendMessage::requestType::CPUT ||
																	msg.getReqMsg().reqType == backendMessage::requestType::DELETE ||
																	msg.getReqMsg().reqType == backendMessage::requestType::APPEND))
			{
				offset = logRequest(msg);
			}
			else if (msg.msgType == backendMessage::messageType::Notify &&
					 (msg.getNotifyMsg().reqType == backendMessage::requestType::PUT ||
					  msg.getNotifyMsg().reqType == backendMessage::requestType::CPUT ||
					  msg.getNotifyMsg().reqType == backendMessage::requestType::DELETE ||
					  msg.getNotifyMsg().reqType == backendMessage::requestType::APPEND))
			{
				offset = logRequest(msg);
			}
			else if (msg.msgType == backendMessage::messageType::Append)
			{
				offset = logRequest(msg);
			}
			if (offset < 0)
			{
				fprintf(stderr, "Error: Failed to log request\n");
				// TODO: handle the case that log request fails
			}

			// perform the request if not checkpointing
			pthread_mutex_lock(&queueLock);
			if ((isCheckpointing || queue.size() > 0) && msg.msgType != backendMessage::CPAck)
			{
				if (verbose)
				{
					printf("Worker: Queueing incoming message because of checkpointing\n");
				}
				msgId2ClientFd[msg.msgId] = commFd;
				queue.push_back(std::make_tuple(msg, commFd, index, offset));
				pthread_mutex_unlock(&queueLock);
			}
			else
			{
				pthread_mutex_unlock(&queueLock);
				performRequest(msg, commFd, index, offset);
			}

			msgSize = msg.getSerializedSize();
			printf("Worker: Message size: %d\n", msgSize);
			int dataLeft = rcvd - msgSize;
			printf("Worker: Data left: %d\n", dataLeft);
			memmove(buffer, buffer + msgSize, dataLeft);
			memset(buffer + dataLeft, 0, BUFFERLENGTH - dataLeft);
			rcvd = dataLeft;
		}
	}

	close(commFd);
	pthread_mutex_lock(&lock);
	fds[index] = 0;
	free(buffers[index]);
	buffers[index] = NULL;
	fdCount--;
	pthread_mutex_unlock(&lock);
	pthread_exit(NULL);
}

/*
 * The handler for CRTL+C interrupt signal
 * Input: signal, the signal that's being handled
 */
void sigHandler(int signal)
{
	if (signal != SIGINT)
	{
		return;
	}

	if (verbose)
		std::cout << "Server shutting down\n";

	while (isLogging) {}

	// close the sockets
	shuttingDown = true;

	// close the fds
	for (int index = 0; index < NUMTHREADS; index++)
	{
		if (fds[index] != 0)
		{
			close(fds[index]);
		}
	}

	for (pthread_t tid : threads)
	{
		if (tid == 0)
			continue;
		pthread_cancel(tid);
		pthread_join(tid, NULL);
		if (verbose)
			std::cerr << "Server join tid " << tid << "\n";
	}
	pthread_cancel(pingThread);
	pthread_join(pingThread, NULL);
	pthread_cancel(coordThread);
	pthread_join(coordThread, NULL);

	pthread_mutex_destroy(&lock);
	pthread_mutex_destroy(&logFileMutex);
	pthread_mutex_destroy(&cpMutex);
	pthread_mutex_destroy(&queueLock);
	pthread_mutex_destroy(&outQueueLock);

	for (auto iter = userTableLocks.begin(); iter != userTableLocks.end();
		 iter++)
	{
		for (auto iter2 = iter->second.begin(); iter2 != iter->second.end();
			 iter2++)
		{
			pthread_mutex_destroy(&iter2->second);
		}
	}

	for (auto iter = fileTableLocks.begin(); iter != fileTableLocks.end();
		 iter++)
	{
		for (auto iter2 = iter->second.begin(); iter2 != iter->second.end();
			 iter2++)
		{
			pthread_mutex_destroy(&iter2->second);
		}
	}

	for (auto iter = inboxTableLocks.begin(); iter != inboxTableLocks.end();
		 iter++)
	{
		for (auto iter2 = iter->second.begin(); iter2 != iter->second.end();
			 iter2++)
		{
			pthread_mutex_destroy(&iter2->second);
		}
	}

	for (auto iter = fileRawColsLocks.begin(); iter != fileRawColsLocks.end(); iter++)
	{
		pthread_mutex_destroy(&iter->second);
	}

	for (auto iter = userRawColsLocks.begin(); iter != userRawColsLocks.end(); iter++)
	{
		pthread_mutex_destroy(&iter->second);
	}

	for (auto iter = inboxRawColsLocks.begin(); iter != inboxRawColsLocks.end(); iter++)
	{
		pthread_mutex_destroy(&iter->second);
	}

	for (auto iter = counterLocks.begin(); iter != counterLocks.end(); iter++)
	{
		pthread_mutex_destroy(&iter->second);
	}

	close(ownSocket);
	close(coordSocket);

	for (struct threadArgs *arg : args)
	{
		if (arg != NULL)
		{
			// if (verbose)
			// {
			// 	std::cout << "freeing arg " << arg << "\n";
			// }
			free(arg);
			arg = NULL;
		}
	}

	for (int index = 0; index < NUMTHREADS; index++)
	{
		if (buffers[index] != NULL)
		{
			free(buffers[index]);
			buffers[index] = NULL;
		}
	}

	free(coordBuffer);
	coordBuffer = NULL;
	exit(0);
}

/*
 * A helper function that put a value in the in-memory table
 * Input: currTable, the current table
 * 		  currTableLocks, the locks for the current table
 * 		  currRawCols, the raw columns of the current table
 * 		  currRawColsLocks, the locks for the raw columns of the current table
 * 		  row, the row of the cell
 * 		  col, the column of the cell
 * 		  rawCol, the raw column of the cell
 * 		  val, the value to put into the cell
 */
void putToTable(
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable,
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks,
	std::map<std::string, std::set<std::tuple<std::string, int>>> *currRawCols,
	std::map<std::string, pthread_mutex_t> *currRawColsLocks,
	std::string row, std::string col, std::string rawCol, std::string val, int isEnd,
	bool isAppend, off_t logOffset)
{
	if (verbose)
	{
		std::cout << "put to table function called\n";
	}
	// no such row
	if (currTable->find(row) == currTable->end())
	{
		if (verbose)
		{
			std::cout << "putToTable no such row\n";
		}
		// new row
		std::map<std::string, std::tuple<std::string, int, off_t, std::string>> newRow;
		currTable->insert({row, newRow});
		if (verbose)
			std::cout << "putToTable new row inserted\n";

		// new row locks
		std::map<std::string, pthread_mutex_t> newLockRow;
		currTableLocks->insert({row, newLockRow});
		if (verbose)
			std::cout << "putToTable new row locks inserted\n";

		// new raw columns
		std::set<std::tuple<std::string, int>> newRawCols;
		currRawCols->insert({row, newRawCols});
		if (verbose)
			std::cout << "putToTable new raw columns inserted\n";

		// new raw columns locks
		pthread_mutex_t newRowLock;
		pthread_mutex_init(&newRowLock, NULL);
		currRawColsLocks->insert({row, newRowLock});
		if (verbose)
			std::cout << "putToTable new raw columns locks inserted\n";
	}

	// write the put
	if (currTable->at(row).find(col) == currTable->at(row).end())
	{
		// no such column
		if (verbose)
		{
			std::cout << "putToTable no such column\n";
		}
		// new column lock
		pthread_mutex_t newLock;
		pthread_mutex_init(&newLock, NULL);
		currTableLocks->at(row).insert({col, newLock});
		if (verbose)
			std::cout << "putToTable new column lock inserted\n";

		// new column
		pthread_mutex_lock(&currTableLocks->at(row).at(col));
		currTable->at(row).insert(
			{col, std::make_tuple("add", isEnd, logOffset, val)});
		tablesSize += val.size();
		if (verbose)
		{
			std::cout << "Insert rol (" << col << ") at row: " << row << "\n";
		}
		pthread_mutex_unlock(&currTableLocks->at(row).at(col));

		// new raw column
		pthread_mutex_lock(&currRawColsLocks->at(row));
		currRawCols->at(row).insert(std::make_tuple(rawCol, 1));
		pthread_mutex_unlock(&currRawColsLocks->at(row));
		if (verbose)
			std::cout << "putToTable new raw column inserted\n";
	}
	else
	{
		if (verbose)
			std::cout << "putToTable has such column\n";
		pthread_mutex_lock(&currTableLocks->at(row).at(col));
		if (isAppend)
		{
			if (verbose)
				std::cout << "putToTable append\n";
			std::string currVal = std::get<3>(currTable->at(row).at(col));
			currTable->at(row)[col] = std::make_tuple("add", isEnd, logOffset, currVal + val);
			tablesSize += val.size();
		}
		else
		{
			if (verbose)
				std::cout << "putToTable add\n";
			std::string currVal = std::get<3>(currTable->at(row).at(col));
			currTable->at(row)[col] = std::make_tuple("add", isEnd, logOffset, val);
			tablesSize += (val.size() - currVal.size());
		}
		pthread_mutex_unlock(&currTableLocks->at(row).at(col));

		pthread_mutex_lock(&currRawColsLocks->at(row));
		std::tuple<std::string, int> currTuple = std::make_tuple(rawCol, 0);
		if (currRawCols->at(row).find(currTuple) != currRawCols->at(row).end())
		{
			currRawCols->at(row).erase(currTuple);
		}
		currRawCols->at(row).insert(std::make_tuple(rawCol, 1));
		pthread_mutex_unlock(&currRawColsLocks->at(row));
	}
	if (verbose)
	{
		std::cout << "putToTable done\n";
		// std::cout << "table size afterward: " << currTable->size() << "\n";
	}
}

/*
 * A function that puts a value into a cell
 * Input: table, the name of the table
 * 		  row, the row of the cell
 * 		  col, the column of the cell
 * 		  rawCol, the raw column of the cell
 * 		  val, the val to put into the cell
 * 		  commFd, the fd to send back the response
 * 		  index, the thread index
 */
void put(std::string table, std::string row, std::string col, std::string rawCol, std::string val,
		 int commFd, int index, int isEnd, off_t logOffset)
{
	if (verbose)
	{
		std::cout << "------------------------------------------------------\n";
		std::cout << "PUT row: " << row << "\n";
		std::cout << "PUT column: " << col << "\n";
		std::cout << "PUT raw column: " << rawCol << "\n";
	}
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable =
		&userTable;
	// if (verbose)
	// {
	// 	std::cerr << "PUT initial table size: " << currTable->size() << "\n";
	// }
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks =
		&userTableLocks;
	std::map<std::string, std::set<std::tuple<std::string, int>>> *currRawCols = &userRawCols;
	std::map<std::string, pthread_mutex_t> *currRawColsLocks = &userRawColsLocks;

	if (table == "UserInfoTable")
	{
		currTable = &userTable;
		currTableLocks = &userTableLocks;
		currRawCols = &userRawCols;
		currRawColsLocks = &userRawColsLocks;
	}
	else if (table == "UserFileTable")
	{
		currTable = &fileTable;
		currTableLocks = &fileTableLocks;
		currRawCols = &fileRawCols;
		currRawColsLocks = &fileRawColsLocks;
	}
	else if (table == "InboxTable")
	{
		currTable = &inboxTable;
		currTableLocks = &inboxTableLocks;
		currRawCols = &inboxRawCols;
		currRawColsLocks = &inboxRawColsLocks;
	}
	else
	{
		// no matching table
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching table");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	if (groupRole == "primary")
	{
		if (verbose)
		{
			std::cout << "PUT primary.\n";
		}
		// forward to all the secondaries
		backendMessage notifyMsg = backendMessage(backendMessage::Notify,
												  msgIds[index], 1);
		notifyMsg.setNotifyMsg(msgIds[index], backendMessage::requestType::PUT,
							   "", table, row, rawCol, val);
		for (std::string secondaryIpPort : secondaryIpPorts)
		{
			forwardToPeers(notifyMsg, secondaryIpPort);
		}

		msgId2ClientFd[msgIds[index]] = commFd;

		if (verbose)
		{
			std::cout << "PUT ready to put to table\n";
		}
		putToTable(currTable, currTableLocks, currRawCols, currRawColsLocks, row, col, rawCol, val, isEnd, false,
				   logOffset);
		// if (verbose)
		// {
		// 	std::cerr << "table size after putToTable: " << currTable->size()
		// 			  << "\n";
		// }

		if (counterLocks.find(msgIds[index]) == counterLocks.end())
		{
			if (verbose)
				std::cout << "counterLocks not found\n";
			// msgIds[index] not in counterLocks
			pthread_mutex_t newLock;
			pthread_mutex_init(&newLock, NULL);
			counterLocks.insert({msgIds[index], newLock});
		}
		pthread_mutex_lock(&counterLocks[msgIds[index]]);
		if (ackCounter.find(msgIds[index]) == ackCounter.end())
		{
			if (verbose)
				std::cout << "ackCounter not found\n";
			ackCounter[msgIds[index]] = 1;
		}
		else
		{
			if (verbose)
				std::cout << "ackCounter found\n";
			ackCounter[msgIds[index]]++;
			if (ackCounter[msgIds[index]] == secondaryIpPorts.size() + 1)
			{
				deliverRsp(index);
			}
		}
		pthread_mutex_unlock(&counterLocks[msgIds[index]]);

		// no secondary
		if (secondariesReady == 0)
		{
			if (verbose)
			{
				std::cout << "No secondary is ready for work.\n";
			}
			std::vector<char> rspBuffer;
			backendMessage rspMsg = backendMessage(backendMessage::Rsp,
												   msgIds[index], 1);
			rspMsg.setRspMsg(backendMessage::responseType::OK,
							 "Command implemented");
			printf("rspMsgToClient:\n");
			rspMsg.printMsg();
			rspMsg.serialize(rspBuffer);
			write(msgId2ClientFd[msgIds[index]], rspBuffer.data(),
				  rspBuffer.size());
			cleanUpMsgIdMaps(msgIds[index]);
		}
	}
	else
	{
		if (verbose)
			std::cout << "PUT secondary.\n";
		// secondary
		msgId2ClientFd[msgIds[index]] = commFd;

		// forward to primary
		backendMessage notifyMsg = backendMessage(backendMessage::Notify,
												  msgIds[index], 1);
		notifyMsg.setNotifyMsg(msgIds[index], backendMessage::requestType::PUT,
							   ownIp + ":" + std::to_string(ownPort), table, row, rawCol, val);
		forwardToPeers(notifyMsg, primaryIpPort);
	}
	// if (verbose)
	// {
	// 	std::cerr << "PUT final table size: " << currTable->size() << "\n";
	// }
}

/*
 * A function that appends a value to a cell
 * Input: table, the name of the table
 * 		  row, the row of the cell
 * 		  col, the column of the cell
 * 		  rawCol, the raw column of the cell
 * 		  val, the val to put into the cell
 * 		  commFd, the fd to send back the response
 * 		  index, the thread index
 */
void append(std::string table, std::string row, std::string col, std::string rawCol,
			std::string val, int isEnd, off_t logOffset, int commFd, int index)
{
	if (verbose)
	{
		std::cout << "------------------------------------------------------\n";
		std::cout << "append row: " << row << "\n";
		std::cout << "append column: " << col << "\n";
		std::cout << "append raw column: " << rawCol << "\n";
	}
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable =
		&userTable;
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks =
		&userTableLocks;
	std::map<std::string, std::set<std::tuple<std::string, int>>> *currRawCols = &userRawCols;
	std::map<std::string, pthread_mutex_t> *currRawColsLocks = &userRawColsLocks;

	if (table == "UserInfoTable")
	{
		currTable = &userTable;
		currTableLocks = &userTableLocks;
		currRawCols = &userRawCols;
		currRawColsLocks = &userRawColsLocks;
	}
	else if (table == "UserFileTable")
	{
		currTable = &fileTable;
		currTableLocks = &fileTableLocks;
		currRawCols = &fileRawCols;
		currRawColsLocks = &fileRawColsLocks;
	}
	else if (table == "InboxTable")
	{
		currTable = &inboxTable;
		currTableLocks = &inboxTableLocks;
		currRawCols = &inboxRawCols;
		currRawColsLocks = &inboxRawColsLocks;
	}
	else
	{
		// no matching table
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching table");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	// check if the cell exists in memory
	if (currTable->find(row) == currTable->end() || currTable->at(row).find(col) == currTable->at(row).end())
	{
		// not in memory
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No cell exists for the append message");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	if (groupRole == "primary")
	{
		// forward to all the secondaries
		backendMessage notifyMsg = backendMessage(backendMessage::Notify,
												  msgIds[index], 1);
		notifyMsg.setNotifyMsg(msgIds[index],
							   backendMessage::requestType::APPEND, "", table, row, rawCol, val);
		for (std::string secondaryIpPort : secondaryIpPorts)
		{
			forwardToPeers(notifyMsg, secondaryIpPort);
		}

		msgId2ClientFd[msgIds[index]] = commFd;
		putToTable(currTable, currTableLocks, currRawCols, currRawColsLocks, row, col, rawCol, val, isEnd, true,
				   logOffset);

		if (counterLocks.find(msgIds[index]) == counterLocks.end())
		{
			// msgIds[index] not in counterLocks
			pthread_mutex_t newLock;
			pthread_mutex_init(&newLock, NULL);
			counterLocks.insert({msgIds[index], newLock});
		}
		pthread_mutex_lock(&counterLocks[msgIds[index]]);
		if (ackCounter.find(msgIds[index]) == ackCounter.end())
		{
			ackCounter[msgIds[index]] = 1;
		}
		else
		{
			ackCounter[msgIds[index]]++;
			if (ackCounter[msgIds[index]] == secondaryIpPorts.size() + 1)
			{
				deliverRsp(index);
			}
		}
		pthread_mutex_unlock(&counterLocks[msgIds[index]]);

		// no secondary
		if (secondariesReady == 0)
		{
			std::vector<char> rspBuffer;
			backendMessage rspMsg = backendMessage(backendMessage::Rsp,
												   msgIds[index], 1);
			rspMsg.setRspMsg(backendMessage::responseType::OK,
							 "Command implemented");
			rspMsg.serialize(rspBuffer);
			write(msgId2ClientFd[msgIds[index]], rspBuffer.data(),
				  rspBuffer.size());
			cleanUpMsgIdMaps(msgIds[index]);
		}
	}
	else
	{
		// secondary
		msgId2ClientFd[msgIds[index]] = commFd;

		// forward to primary
		backendMessage notifyMsg = backendMessage(backendMessage::Notify,
												  msgIds[index], 1);
		notifyMsg.setNotifyMsg(msgIds[index],
							   backendMessage::requestType::APPEND,
							   ownIp + ":" + std::to_string(ownPort), table, row, rawCol, val);
		forwardToPeers(notifyMsg, primaryIpPort);
	}
}

void appendOperation(std::map<std::string, std::map<std::string,
													std::tuple<std::string, int, off_t, std::string>>> *currTable,
					 std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks,
					 std::map<std::string, std::set<std::tuple<std::string, int>>> *currRawCols,
					 std::map<std::string, pthread_mutex_t> *currRawColsLocks,
					 std::string row, std::string col, std::string rawCol, std::string val,
					 int isEnd, off_t logOffset)
{
	if (currTable->find(row) == currTable->end() ||
		currTable->at(row).find(col) == currTable->at(row).end())
	{
		fprintf(stderr, "Error: No such cell exists for row %s column %s for append operation\n",
				row.c_str(), col.c_str());
		return;
	}
	putToTable(currTable, currTableLocks, currRawCols, currRawColsLocks, row, col, rawCol, val, isEnd, true, logOffset);
}

/*
 * A function that gets the value of a cell
 * Input: table, the name of the table
 * 		  row, the row of the cell
 * 		  col, the column of the cell
 * 		  commFd, the fd to send back the responses
 * 		  index, the thread index
 */
void get(std::string table, std::string row, std::string col, int commFd,
		 int index)
{
	if (verbose)
	{
		std::cout << "------------------------------------------------------\n";
		std::cout << "GET row: " << row << "\n";
		std::cout << "GET column: " << col << "\n";
	}
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable =
		&userTable;
	// if (verbose)
	// {
	// 	std::cerr << "GET initial table size: " << currTable->size() << "\n";
	// }
	std::map<std::string, std::map<std::string, uint64_t>> *currOffsets =
		&userOffsets;
	pthread_mutex_t *currLock = &userOffsetLock;
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks =
		&userTableLocks;

	if (table == "UserInfoTable")
	{
		currTable = &userTable;
		currOffsets = &userOffsets;
		currLock = &userOffsetLock;
		currTableLocks = &userTableLocks;
	}
	else if (table == "UserFileTable")
	{
		currTable = &fileTable;
		currOffsets = &fileOffsets;
		currLock = &fileOffsetLock;
		currTableLocks = &fileTableLocks;
	}
	else if (table == "InboxTable")
	{
		currTable = &inboxTable;
		currOffsets = &inboxOffsets;
		currLock = &inboxOffsetLock;
		currTableLocks = &inboxTableLocks;
	}
	else
	{
		// no matching table
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching table");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	bool inMem = false;
	bool onDisk = false;

	// rebuild the offsets
	rebuildOffsets(currOffsets,
				   currLock, row, table);

	pthread_mutex_lock(currLock);
	if (currTable->find(row) != currTable->end() && currTable->at(row).find(col) != currTable->at(row).end())
	{
		if (verbose)
		{
			std::cout << "GET in memory\n";
		}
		inMem = true;
	}
	else if (currOffsets->find(row) != currOffsets->end() && currOffsets->at(row).find(col) != currOffsets->at(row).end())
	{
		if (verbose)
		{
			std::cout << "GET on disk\n";
			std::cout << "GET offset: " << currOffsets->at(row).at(col) << "\n";
		}
		onDisk = true;
	}
	pthread_mutex_unlock(currLock);

	if (!inMem && !onDisk)
	{
		// no matching row or column
		if (verbose)
		{
			std::cerr << "GET no matching row or column\n";
			// std::cerr << "GET table size: " << currTable->size() << "\n";
		}
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching row/column");
		rspMsg.serialize(rspBuffer);
		rspMsg.printMsg();
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	bool done = false;

	// the offset within the cell
	off_t cellOffset = 0;
	off_t fileOffset;
	// the offset within the file
	if (onDisk)
	{
		pthread_mutex_lock(currLock);
		fileOffset = currOffsets->at(row).at(col);
		if (verbose) {
			std::cout << "Initial file offset: " << fileOffset << "\n";
		}
	}

	// the size of the cell data as indicated by the integer in the file
	off_t cellSize = -1;

	// the offset from the file offset to the start of the data section
	int dataOffset = -1;

	while (!done)
	{
		if (inMem)
		{
			pthread_mutex_lock(&currTableLocks->at(row).at(col));
			std::string cell = std::get<3>(currTable->at(row).at(col));
			std::string mode = std::get<0>(currTable->at(row).at(col));
			pthread_mutex_unlock(&currTableLocks->at(row).at(col));
			printf("mode: %s\n", mode.c_str());
			if (mode == "delete")
			{
				// deleted
				std::vector<char> rspBuffer;
				backendMessage rspMsg = backendMessage(backendMessage::Rsp,
													   msgIds[index], 1);
				rspMsg.setRspMsg(backendMessage::responseType::ERR, "Deleted");
				rspMsg.serialize(rspBuffer);
				write(fds[index], rspBuffer.data(), rspBuffer.size());
				return;
			}
			std::vector<char> rspBuffer;
			if (cellOffset + CONTENTLENGTH >= cell.size())
			{
				// done
				done = true;
				if (cellOffset == 0)
				{
					// first
					backendMessage rspMsg = backendMessage(backendMessage::Rsp,
														   msgIds[index], 1);
					rspMsg.setRspMsg(backendMessage::responseType::OK, cell);
					rspMsg.serialize(rspBuffer);
				}
				else
				{
					// recurring
					backendMessage rspMsg = backendMessage(
						backendMessage::Append, msgIds[index], 1);
					rspMsg.setAppendMsg(table, row, col,
										cell.substr(cellOffset, cell.size() - cellOffset));
					rspMsg.serialize(rspBuffer);
				}
			}
			else
			{
				// not done
				if (cellOffset == 0)
				{
					// first
					backendMessage rspMsg = backendMessage(backendMessage::Rsp,
														   msgIds[index], 0);
					rspMsg.setRspMsg(backendMessage::responseType::OK,
									 cell.substr(cellOffset, CONTENTLENGTH));
					rspMsg.serialize(rspBuffer);
				}
				else
				{
					// recurring
					backendMessage rspMsg = backendMessage(
						backendMessage::Append, msgIds[index], 0);
					rspMsg.setAppendMsg(table, row, col,
										cell.substr(cellOffset, CONTENTLENGTH));
					rspMsg.serialize(rspBuffer);
				}
				cellOffset += CONTENTLENGTH;
			}
			write(fds[index], rspBuffer.data(), rspBuffer.size());
		}
		else
		{
			// on disk
			std::vector<char> rspBuffer;

			// get file fd
			std::string fileName = path + "/" + table + "/" + row + ".txt";
			if (verbose)
				std::cerr << "File name: " << fileName << "\n";

			int fd = open(fileName.c_str(), O_RDONLY);

			if (cellSize == -1)
			{
				// first time

				// read column just to be sure
				lseek(fd, fileOffset, SEEK_SET);
				char columnBuffer[32];
				read(fd, columnBuffer, 32);
				std::string columnStr(columnBuffer, 32);
				if (verbose) {
					std::cout << "GET on disk column str: " << columnStr << "\n";
				}

				// move to the file offset + 32 bytes for column key + 1 byte for space
				if (verbose) {
					std::cout << "new file offset: " << fileOffset + 33 << "\n";
				}
				lseek(fd, fileOffset + 33, SEEK_SET);

				char sizeBuffer[32];
				read(fd, sizeBuffer, 32);

				// find space
				int spaceIndex = 0;
				while (spaceIndex < 32)
				{
					if (sizeBuffer[spaceIndex] == ' ')
					{
						break;
					}
					spaceIndex++;
				}

				// set up the offsets
				dataOffset = 33 + spaceIndex + 1;
				std::string sizeStr(sizeBuffer, spaceIndex);
				if (verbose) {
					std::cout << "GET on disk cell size str: " << sizeStr << "\n";
				}
				cellSize = (off_t)std::stoul(sizeStr);
				if (verbose)
				{
					std::cout << "GET on disk cell size: " << cellSize << "\n";
				}
			}
			// move to the start of the cell offset
			lseek(fd, fileOffset + dataOffset + cellOffset, SEEK_SET);
			if (cellOffset + CONTENTLENGTH >= cellSize)
			{
				// done
				done = true;
				char contentBuffer[cellSize - cellOffset];
				read(fd, contentBuffer, cellSize - cellOffset);
				std::string contentStr(contentBuffer);
				if (verbose)
				{
					std::cout << "GET on disk content length: " << contentStr.length() << "\n";
				}
				if (cellOffset == 0)
				{
					// first
					backendMessage rspMsg = backendMessage(backendMessage::Rsp,
														   msgIds[index], 1);
					rspMsg.setRspMsg(backendMessage::responseType::OK,
									 contentStr);
					rspMsg.serialize(rspBuffer);
				}
				else
				{
					// recurring
					backendMessage rspMsg = backendMessage(
						backendMessage::Append, msgIds[index], 1);
					rspMsg.setAppendMsg(table, row, col, contentStr);
					rspMsg.serialize(rspBuffer);
				}
			}
			else
			{
				// not done yet
				char contentBuffer[CONTENTLENGTH];
				read(fd, contentBuffer, CONTENTLENGTH);
				std::string contentStr(contentBuffer);
				if (cellOffset == 0)
				{
					// first
					backendMessage rspMsg = backendMessage(backendMessage::Rsp,
														   msgIds[index], 0);
					rspMsg.setRspMsg(backendMessage::responseType::OK,
									 contentStr);
					rspMsg.serialize(rspBuffer);
				}
				else
				{
					// recurring
					backendMessage rspMsg = backendMessage(
						backendMessage::Append, msgIds[index], 0);
					rspMsg.setAppendMsg(table, row, col, contentStr);
					rspMsg.serialize(rspBuffer);
				}
				cellOffset += CONTENTLENGTH;
			}
			close(fd);
			write(fds[index], rspBuffer.data(), rspBuffer.size());
		}
	}
	if (onDisk)
		pthread_mutex_unlock(currLock);
}

bool checkCputCond(
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable,
	std::string table, pthread_mutex_t *currLock,
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks,
	std::map<std::string, std::map<std::string, uint64_t>> *currOffsets,
	std::string row, std::string col, std::string val1, bool sendRsp,
	int commFd, int index)
{
	// check if the match value match
	bool foundMatch = true;
	bool inMem = false;
	bool onDisk = false;

	// rebuild the offsets
	rebuildOffsets(currOffsets,
				   currLock, row, table);

	pthread_mutex_lock(currLock);
	if (currTable->find(row) != currTable->end() && currTable->at(row).find(col) != currTable->at(row).end())
	{
		inMem = true;
		if (verbose)
		{
			std::cout << "checkCputCond inMem\n";
		}
	}
	else if (currOffsets->find(row) != currOffsets->end() && currOffsets->at(row).find(col) != currOffsets->at(row).end())
	{
		onDisk = true;
		if (verbose)
		{
			std::cout << "checkCputCond onDisk\n";
		}
	}
	pthread_mutex_unlock(currLock);

	if (!inMem && !onDisk)
	{
		foundMatch = false;
		if (verbose)
		{
			std::cout << "checkCputCond not found\n";
		}
		if (!sendRsp)
			return foundMatch;
		// no matching row or column
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching row/column");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return foundMatch;
	}

	if (inMem)
	{
		pthread_mutex_lock(&currTableLocks->at(row).at(col));
		std::string cell = std::get<3>(currTable->at(row).at(col));
		std::string mode = std::get<0>(currTable->at(row).at(col));
		pthread_mutex_unlock(&currTableLocks->at(row).at(col));
		if (cell != val1 || mode == "deleted")
		{
			if (verbose)
			{
				std::cout << "checkCputCond deleted\n";
			}
			// not match
			foundMatch = false;
			if (!sendRsp)
				return foundMatch;
			std::vector<char> rspBuffer;
			backendMessage rspMsg = backendMessage(backendMessage::Rsp,
												   msgIds[index], 1);
			rspMsg.setRspMsg(backendMessage::responseType::ERR,
							 "Value does not match");
			rspMsg.serialize(rspBuffer);
			write(fds[index], rspBuffer.data(), rspBuffer.size());
			return foundMatch;
		}
	}
	else
	{
		// on disk

		// get file fd
		std::string fileName = path + "/" + table + "/" + row + ".txt";
		if (verbose)
			std::cerr << "File name: " << fileName << "\n";

		int fd = open(fileName.c_str(), O_RDONLY);

		// the offset within the file
		pthread_mutex_lock(currLock);
		int fileOffset = currOffsets->at(row).at(col);

		// move to the file offset + 32 bytes for column key + 1 byte for space
		lseek(fd, fileOffset + 33, SEEK_SET);

		char sizeBuffer[32];
		read(fd, sizeBuffer, 32);

		// find space
		int spaceIndex = 0;
		while (spaceIndex < 32)
		{
			if (sizeBuffer[spaceIndex] == ' ')
			{
				break;
			}
			spaceIndex++;
		}

		// set up the offsets
		int dataOffset = 33 + spaceIndex + 1;
		std::string sizeStr(sizeBuffer, spaceIndex);
		int cellSize = std::stoi(sizeStr);

		// move to the start of the data offset
		lseek(fd, fileOffset + dataOffset, SEEK_SET);
		char contentBuffer[cellSize];
		read(fd, contentBuffer, cellSize);
		std::string contentStr(contentBuffer);

		if (contentStr != val1)
		{
			// not match
			foundMatch = false;
			if (!sendRsp)
			{
				close(fd);
				pthread_mutex_unlock(currLock);
				return foundMatch;
			}
			std::vector<char> rspBuffer;
			backendMessage rspMsg = backendMessage(backendMessage::Rsp,
												   msgIds[index], 1);
			rspMsg.setRspMsg(backendMessage::responseType::ERR,
							 "Value does not match");
			rspMsg.serialize(rspBuffer);
			write(fds[index], rspBuffer.data(), rspBuffer.size());
			close(fd);
			pthread_mutex_unlock(currLock);
			return foundMatch;
		}
		close(fd);
		pthread_mutex_unlock(currLock);
	}
	return foundMatch;
}

/*
 * A function that conditionally puts a value into a cell
 * Input: table, the name of the table
 * 		  row, the row of the cell
 * 		  col, the column of the cell
 * 		  val1, the val to compare
 * 		  val2, the val to put into the cell
 * 		  commFd, the fd to send back the response
 * 		  index, the thread index
 */
void cPut(std::string table, std::string row, std::string col, std::string rawCol, std::string val1,
		  std::string val2, int commFd, int index, int isEnd, off_t logOffset)
{
	if (verbose)
	{
		std::cout << "------------------------------------------------------\n";
		std::cout << "CPUT row: " << row << "\n";
		std::cout << "CPUT column: " << col << "\n";
		std::cout << "CPUT raw column: " << rawCol << "\n";
	}

	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable =
		&userTable;
	std::map<std::string, std::map<std::string, uint64_t>> *currOffsets =
		&userOffsets;
	pthread_mutex_t *currLock = &userOffsetLock;
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks =
		&userTableLocks;
	std::map<std::string, std::set<std::tuple<std::string, int>>> *currRowCols = &userRawCols;
	std::map<std::string, pthread_mutex_t> *currRowColsLock = &userRawColsLocks;

	if (table == "UserInfoTable")
	{
		currTable = &userTable;
		currOffsets = &userOffsets;
		currLock = &userOffsetLock;
		currTableLocks = &userTableLocks;
		currRowCols = &userRawCols;
		currRowColsLock = &userRawColsLocks;
	}
	else if (table == "UserFileTable")
	{
		currTable = &fileTable;
		currOffsets = &fileOffsets;
		currLock = &fileOffsetLock;
		currTableLocks = &fileTableLocks;
		currRowCols = &fileRawCols;
		currRowColsLock = &fileRawColsLocks;
	}
	else if (table == "InboxTable")
	{
		currTable = &inboxTable;
		currOffsets = &inboxOffsets;
		currLock = &inboxOffsetLock;
		currTableLocks = &inboxTableLocks;
		currRowCols = &inboxRawCols;
		currRowColsLock = &inboxRawColsLocks;
	}
	else
	{
		// no matching table
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching table");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	if (!checkCputCond(currTable, table, currLock, currTableLocks, currOffsets,
					   row, col, val1, true, commFd, index))
		return;

	if (groupRole == "primary")
	{
		// forward to all the secondaries
		if (verbose)
		{
			std::cout << "Cput primary\n";
		}
		backendMessage notifyMsg = backendMessage(backendMessage::Notify,
												  msgIds[index], 1);
		notifyMsg.setNotifyMsg(msgIds[index], backendMessage::requestType::PUT,
							   "", table, row, rawCol, val2);
		for (std::string secondaryIpPort : secondaryIpPorts)
		{
			forwardToPeers(notifyMsg, secondaryIpPort);
		}

		msgId2ClientFd[msgIds[index]] = commFd;

		putToTable(currTable, currTableLocks, currRowCols, currRowColsLock, row, col, rawCol, val2, isEnd, false,
				   logOffset);

		// TODO: handle put fail

		if (counterLocks.find(msgIds[index]) == counterLocks.end())
		{
			// msgIds[index] not in counterLocks
			pthread_mutex_t newLock;
			pthread_mutex_init(&newLock, NULL);
			counterLocks.insert({msgIds[index], newLock});
		}
		pthread_mutex_lock(&counterLocks[msgIds[index]]);
		if (ackCounter.find(msgIds[index]) == ackCounter.end())
		{
			ackCounter[msgIds[index]] = 1;
		}
		else
		{
			ackCounter[msgIds[index]]++;
			if (ackCounter[msgIds[index]] == secondaryIpPorts.size() + 1)
			{
				deliverRsp(index);
			}
		}
		pthread_mutex_unlock(&counterLocks[msgIds[index]]); // if PUT failed, should be 0
		// no secondary
		if (secondariesReady == 0)
		{
			if (verbose)
			{
				std::cout << "Cput primary and no secondary\n";
			}
			std::vector<char> rspBuffer;
			backendMessage rspMsg = backendMessage(backendMessage::Rsp,
												   msgIds[index], 1);
			rspMsg.setRspMsg(backendMessage::responseType::OK,
							 "Command implemented");
			rspMsg.serialize(rspBuffer);
			write(msgId2ClientFd[msgIds[index]], rspBuffer.data(),
				  rspBuffer.size());
			cleanUpMsgIdMaps(msgIds[index]);
		}
	}
	else
	{
		// secondary
		if (verbose)
		{
			std::cout << "Cput primary secondary\n";
		}
		msgId2ClientFd[msgIds[index]] = commFd;

		// forward to primary
		backendMessage notifyMsg = backendMessage(backendMessage::Notify,
												  msgIds[index], 1);
		notifyMsg.setNotifyMsg(msgIds[index], backendMessage::requestType::PUT,
							   ownIp + ":" + std::to_string(ownPort), table, row, rawCol, val2);
		forwardToPeers(notifyMsg, primaryIpPort);
	}
}

/*
 * A function that checks condition for delete operation
 * Input: currTable, the table to delete from
 * 		  currOffsets, the offsets of the table
 * 		  currLock, the lock of the table
 * 		  currTableLocks, the locks of the table
 * 		  table, the name of the table
 * 		  row, the row of the cell
 * 		  col, the column of the cell
 * 		  index, the thread index
 * 		  logOffset, the offset of the log
 */
std::string checkDeleteCond(
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable,
	std::map<std::string, std::map<std::string, uint64_t>> *currOffsets,
	pthread_mutex_t *currOffsetLock,
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks,
	std::string table, std::string row, std::string col)
{
	// check if the match value match
	bool inMem = false;
	bool onDisk = false;

	// rebuild the offsets
	rebuildOffsets(currOffsets,
				   currOffsetLock, row, table);

	pthread_mutex_lock(currOffsetLock);
	if (currTable->find(row) != currTable->end() && currTable->at(row).find(col) != currTable->at(row).end())
	{
		inMem = true;
	}
	else if (currOffsets->find(row) != currOffsets->end() && currOffsets->at(row).find(col) != currOffsets->at(row).end())
	{
		onDisk = true;
	}
	pthread_mutex_unlock(currOffsetLock);

	if (!inMem && !onDisk)
	{
		// no matching row or column
		if (verbose)
		{
			std::cerr << "DELETE no matching row or column\n";
			// std::cerr << "DELETE table size: " << currTable->size() << "\n";
		}
		return "No matching row/column";
	}

	if (inMem)
	{
		pthread_mutex_lock(&currTableLocks->at(row).at(col));
		if (std::get<0>(currTable->at(row)[col]) == "delete")
		{
			// already deleted
			pthread_mutex_unlock(&currTableLocks->at(row).at(col));
			return "Already deleted";
		}
		pthread_mutex_unlock(&currTableLocks->at(row).at(col));
	}

	return "OK";
}

/*
 * A function that record delete operation of a cell
 * Input: currTable, the table to delete from
 * 		  currOffsets, the offsets of the table
 * 		  currLock, the lock of the table
 * 		  currTableLocks, the locks of the table
 * 		  table, the name of the table
 * 		  row, the row of the cell
 * 		  col, the column of the cell
 * 		  index, the thread index
 * 		  logOffset, the offset of the log
 */

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
	off_t logOffset)
{
	// check if the match value match
	bool onDisk = false;

	// rebuild the offsets
	rebuildOffsets(currOffsets,
				   currLock, row, table);

	pthread_mutex_lock(currLock);
	if (currOffsets->find(row) != currOffsets->end() && currOffsets->at(row).find(col) != currOffsets->at(row).end())
	{
		onDisk = true;
	}
	pthread_mutex_unlock(currLock);

	// no such row
	if (onDisk && currTable->find(row) == currTable->end())
	{
		std::map<std::string, std::tuple<std::string, int, off_t, std::string>> newRow;
		currTable->insert({row, newRow});
		std::map<std::string, pthread_mutex_t> newLockRow;
		currTableLocks->insert({row, newLockRow});
		std::set<std::tuple<std::string, int>> newRawCols;
		currRawCols->insert({row, newRawCols});
		pthread_mutex_t newLock;
		pthread_mutex_init(&newLock, NULL);
		currRawColsLocks->insert({row, newLock});
	}

	printf("DELETE: raw col %s\n", rawCol.c_str());
	// write the delete
	if (onDisk && currTable->at(row).find(col) == currTable->at(row).end())
	{
		// no such column
		pthread_mutex_t newLock;
		pthread_mutex_init(&newLock, NULL);
		currTableLocks->at(row).insert({col, newLock});
		pthread_mutex_lock(&currTableLocks->at(row).at(col));
		currTable->at(row).insert(
			{col, std::make_tuple("delete", 1, logOffset, "")});
		pthread_mutex_unlock(&currTableLocks->at(row).at(col));
		pthread_mutex_lock(&currRawColsLocks->at(row));
		currRawCols->at(row).insert(std::make_tuple(rawCol, 0));
		pthread_mutex_unlock(&currRawColsLocks->at(row));
	}
	else
	{
		pthread_mutex_lock(&currTableLocks->at(row).at(col));
		std::string currCell = std::get<3>(currTable->at(row)[col]);
		currTable->at(row)[col] = std::make_tuple("delete", 1, logOffset, "");
		tablesSize -= currCell.size();
		pthread_mutex_unlock(&currTableLocks->at(row).at(col));

		pthread_mutex_lock(&currRawColsLocks->at(row));
		// std::tuple<std::string, int> currTuple = std::make_tuple(rawCol, 1);
		// if (currRawCols->at(row).find({rawCol, 1}) != currRawCols->at(row).end())
		// {
			// printf("found previously existed raw col %s\n", rawCol.c_str());
			currRawCols->at(row).erase({rawCol, 1});
		// }
		currRawCols->at(row).insert(std::make_tuple(rawCol, 0));
		pthread_mutex_unlock(&currRawColsLocks->at(row));
	}
	printf("rawCols after delete: ");
	for (auto it = currRawCols->at(row).begin(); it != currRawCols->at(row).end(); it++)
	{
		std::cout << std::get<0>(*it) << " ";
		std::cout << std::get<1>(*it) << " " << std::endl;
	}
}

/*
 * A function that deletes a cell
 * Input: table, the name of the table
 * 		  row, the row of the cell
 * 		  col, the column of the cell
 * 		  rawCol, the raw column of the cell
 * 		  commFd, the fd to send back the response
 * 		  index, the thread index
 */
void deleteCell(std::string table, std::string row, std::string col, std::string rawCol, int commFd,
				int index, off_t logOffset)
{
	if (verbose)
	{
		std::cout << "------------------------------------------------------\n";
		std::cout << "DELETE row: " << row << "\n";
		std::cout << "DELETE column: " << col << "\n";
		std::cout << "DELETE raw column: " << rawCol << "\n";
	}
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable =
		&userTable;
	std::map<std::string, std::map<std::string, uint64_t>> *currOffsets =
		&userOffsets;
	pthread_mutex_t *currLock = &userOffsetLock;
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks =
		&userTableLocks;
	std::map<std::string, std::set<std::tuple<std::string, int>>> *currRawCols;
	std::map<std::string, pthread_mutex_t> *currRawColsLocks;

	if (table == "UserInfoTable")
	{
		currTable = &userTable;
		currOffsets = &userOffsets;
		currLock = &userOffsetLock;
		currTableLocks = &userTableLocks;
		currRawCols = &userRawCols;
		currRawColsLocks = &userRawColsLocks;
	}
	else if (table == "UserFileTable")
	{
		currTable = &fileTable;
		currOffsets = &fileOffsets;
		currLock = &fileOffsetLock;
		currTableLocks = &fileTableLocks;
		currRawCols = &fileRawCols;
		currRawColsLocks = &fileRawColsLocks;
	}
	else if (table == "InboxTable")
	{
		currTable = &inboxTable;
		currOffsets = &inboxOffsets;
		currLock = &inboxOffsetLock;
		currTableLocks = &inboxTableLocks;
		currRawCols = &inboxRawCols;
		currRawColsLocks = &inboxRawColsLocks;
	}
	else
	{
		// no matching table
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching table");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	std::string res = checkDeleteCond(currTable, currOffsets, currLock,
									  currTableLocks, table, row, col);
	if (res == "No matching row/column")
	{
		// no matching row or column
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching row/column");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	// already deleted
	if (res == "Already deleted")
	{
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR, "Already deleted");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	if (groupRole == "primary")
	{
		msgId2ClientFd[msgIds[index]] = commFd;
		// forward to all the secondaries
		backendMessage notifyMsg = backendMessage(backendMessage::Notify,
												  msgIds[index], 1);
		notifyMsg.setNotifyMsg(msgIds[index],
							   backendMessage::requestType::DELETE, "", table, row, rawCol, "");
		for (std::string secondaryIpPort : secondaryIpPorts)
		{
			forwardToPeers(notifyMsg, secondaryIpPort);
		}
		// no secondary
		if (secondariesReady == 0)
		{
			std::vector<char> rspBuffer;
			backendMessage rspMsg = backendMessage(backendMessage::Rsp,
												   msgIds[index], 1);
			rspMsg.setRspMsg(backendMessage::responseType::OK,
							 "Command implemented");
			rspMsg.serialize(rspBuffer);
			write(commFd, rspBuffer.data(), rspBuffer.size());
			cleanUpMsgIdMaps(msgIds[index]);
		}
	}
	else
	{
		// secondary
		msgId2ClientFd[msgIds[index]] = commFd;

		// forward to primary
		backendMessage notifyMsg = backendMessage(backendMessage::Notify,
												  msgIds[index], 1);
		notifyMsg.setNotifyMsg(msgIds[index],
							   backendMessage::requestType::DELETE,
							   ownIp + ":" + std::to_string(ownPort), table, row, rawCol, "");
		forwardToPeers(notifyMsg, primaryIpPort);
	}

	if (groupRole == "primary")
	{
		deleteOperation(currTable, currOffsets, &userOffsetLock, currTableLocks, currRawCols, currRawColsLocks,
						table, row, col, rawCol, logOffset);
		if (counterLocks.find(msgIds[index]) == counterLocks.end())
		{
			// msgIds[index] not in counterLocks
			pthread_mutex_t newLock;
			pthread_mutex_init(&newLock, NULL);
			counterLocks.insert({msgIds[index], newLock});
		}
		pthread_mutex_lock(&counterLocks[msgIds[index]]);
		if (ackCounter.find(msgIds[index]) == ackCounter.end())
		{
			ackCounter[msgIds[index]] = 1;
		}
		else
		{
			ackCounter[msgIds[index]]++;
			if (ackCounter[msgIds[index]] == secondaryIpPorts.size() + 1)
			{
				deliverRsp(index);
			}
		}
		pthread_mutex_unlock(&counterLocks[msgIds[index]]);
	}
}

/*
 * A function that handle a verify message
 * Input: row, the row of the cell
 * 		  password, the password to verify
 * 		  commFd, the fd to send back the response
 * 		 index, the thread index
 */
void verify(std::string row, std::string password, int commFd, int index)
{
	if (verbose)
	{
		std::cout << "------------------------------------------------------\n";
		std::cout << "VERIFY row: " << row << "\n";
		std::cout << "VERIFY password: " << password << "\n";
	}

	bool inMem = false;
	bool onDisk = false;
	std::string passwordColName = computeDigest("password");

	// rebuild the offsets
	rebuildOffsets(&userOffsets,
				   &userOffsetLock, row, "UserInfoTable");

	pthread_mutex_lock(&userOffsetLock);
	if (userTable.find(row) != userTable.end() && userTable.at(row).find(passwordColName) != userTable.at(row).end())
	{
		inMem = true;
	}
	else if (userOffsets.find(row) != userOffsets.end() && userOffsets.at(row).find(passwordColName) != userOffsets.at(row).end())
	{
		onDisk = true;
	}
	pthread_mutex_unlock(&userOffsetLock);

	if (!inMem && !onDisk)
	{
		// no matching row or column
		if (verbose)
		{
			std::cerr << "VERIFY no matching row or column\n";
		}
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching row/column");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	// the offset within the file
	off_t fileOffset;
	if (onDisk)
	{
		pthread_mutex_lock(&userOffsetLock);
		fileOffset = userOffsets.at(row).at(passwordColName);
	}

	// the size of the cell data as indicated by the integer in the file
	off_t cellSize = -1;

	// the offset from the file offset to the start of the data section
	int dataOffset = -1;

	if (inMem)
	{
		pthread_mutex_lock(&userTableLocks.at(row).at(passwordColName));
		std::string cell = std::get<3>(userTable.at(row).at(passwordColName));
		std::string mode = std::get<0>(userTable.at(row).at(passwordColName));
		pthread_mutex_unlock(&userTableLocks.at(row).at(passwordColName));
		printf("mode: %s\n", mode.c_str());
		if (mode == "delete")
		{
			// deleted
			std::vector<char> rspBuffer;
			backendMessage rspMsg = backendMessage(backendMessage::Rsp,
												   msgIds[index], 1);
			rspMsg.setRspMsg(backendMessage::responseType::ERR, "Deleted");
			rspMsg.serialize(rspBuffer);
			write(fds[index], rspBuffer.data(), rspBuffer.size());
			return;
		}
		std::vector<char> rspBuffer;
		if (cell == password)
		{
			// verified
			backendMessage rspMsg = backendMessage(backendMessage::Rsp, msgIds[index], 1);
			rspMsg.setRspMsg(backendMessage::responseType::OK, "Verified");
			rspMsg.serialize(rspBuffer);
		}
		else
		{
			// not verified
			backendMessage rspMsg = backendMessage(backendMessage::Rsp, msgIds[index], 1);
			rspMsg.setRspMsg(backendMessage::responseType::ERR, "Wrong password");
			rspMsg.serialize(rspBuffer);
		}
		write(fds[index], rspBuffer.data(), rspBuffer.size());
	}
	else
	{
		// on disk
		std::vector<char> rspBuffer;

		// get file fd
		std::string fileName = path + "/UserInfoTable/" + row + ".txt";
		if (verbose)
			std::cerr << "File name: " << fileName << "\n";

		int fd = open(fileName.c_str(), O_RDONLY);

		// move to the file offset + 32 bytes for column key + 1 byte for space
		lseek(fd, fileOffset + 33, SEEK_SET);

		char sizeBuffer[32];
		read(fd, sizeBuffer, 32);

		// find space
		int spaceIndex = 0;
		while (spaceIndex < 32)
		{
			if (sizeBuffer[spaceIndex] == ' ')
			{
				break;
			}
			spaceIndex++;
		}

		// set up the offsets
		dataOffset = 33 + spaceIndex + 1;
		std::string sizeStr(sizeBuffer, spaceIndex);
		cellSize = (off_t)std::stoul(sizeStr);

		// move to the start of the data offset
		lseek(fd, fileOffset + dataOffset, SEEK_SET);
		char contentBuffer[cellSize];
		read(fd, contentBuffer, cellSize);
		std::string contentStr(contentBuffer);
		if (contentStr == password)
		{
			// verified
			backendMessage rspMsg = backendMessage(backendMessage::Rsp, msgIds[index], 1);
			rspMsg.setRspMsg(backendMessage::responseType::OK, "Verified");
			rspMsg.serialize(rspBuffer);
		}
		else
		{
			// not verified
			backendMessage rspMsg = backendMessage(backendMessage::Rsp, msgIds[index], 1);
			rspMsg.setRspMsg(backendMessage::responseType::ERR, "Wrong password");
			rspMsg.serialize(rspBuffer);
		}

		close(fd);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
	}

	if (onDisk)
		pthread_mutex_unlock(&userOffsetLock);
}

/*
 * A function that handle a getRow message
 * Input: table, the name of the table
 *        row, the row of the cell
 * 		  commFd, the fd to send back the response
 * 		  index, the thread index
 */
void getRow(std::string table, std::string row, int commFd, int index)
{
	if (verbose)
	{
		std::cout << "------------------------------------------------------\n";
		std::cout << "GETROW row: " << row << "\n";
		std::cout << "GETROW table: " << table << "\n";
	}
	std::map<std::string, std::set<std::tuple<std::string, int>>> *currRawCols =
		&userRawCols;
	std::map<std::string, pthread_mutex_t> *currRawColsLocks =
		&userRawColsLocks;
	std::map<std::string, std::map<std::string, uint64_t>> *currOffsets =
		&userOffsets;
	pthread_mutex_t *currLock = &userOffsetLock;

	if (table == "UserInfoTable")
	{
		currRawCols = &userRawCols;
		currRawColsLocks = &userRawColsLocks;
		currOffsets = &userOffsets;
		currLock = &userOffsetLock;
	}
	else if (table == "UserFileTable")
	{
		currRawCols = &fileRawCols;
		currRawColsLocks = &fileRawColsLocks;
		currOffsets = &fileOffsets;
		currLock = &fileOffsetLock;
	}
	else if (table == "InboxTable")
	{
		currRawCols = &inboxRawCols;
		currRawColsLocks = &inboxRawColsLocks;
		currOffsets = &inboxOffsets;
		currLock = &inboxOffsetLock;
	}
	else
	{
		// no matching table
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching table");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	bool inMem = false;
	bool onDisk = false;

	// rebuild the offsets
	rebuildOffsets(currOffsets,
				   currLock, row, table);

	if (currRawCols->find(row) != currRawCols->end())
	{
		inMem = true;
	}
	if (currOffsets->find(row) != currOffsets->end() && currOffsets->at(row).find(allColumnsName) != currOffsets->at(row).end())
	{
		onDisk = true;
	}

	if (!inMem && !onDisk)
	{
		// no matching row or column
		if (verbose)
		{
			std::cerr << "GETROW no matching row or column\n";
		}
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching row/column");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
		return;
	}

	// get the columns
	std::set<std::string> columns;
	std::set<std::string> deletedColumns;

	// get the im-mem columns, differentiate between existing ones and deleted ones
	if (inMem)
	{
		pthread_mutex_lock(&currRawColsLocks->at(row));
		for (auto x : currRawCols->at(row))
		{
			if (verbose)
				std::cerr << "Column: " << std::get<0>(x) << "\n";
			if (std::get<1>(x) == 1)
			{
				if (verbose)
					std::cout << "Inserting column: " << std::get<0>(x) << "\n";
				columns.insert(std::get<0>(x));
			}
			else
			{
				if (verbose)
					std::cout << "Deleting column: " << std::get<0>(x) << "\n";
				deletedColumns.insert(std::get<0>(x));
			}
		}
		pthread_mutex_unlock(&currRawColsLocks->at(row));
	}

	// get the on-disk columns
	if (onDisk)
	{
		pthread_mutex_lock(currLock);
		off_t fileOffset = currOffsets->at(row).at(allColumnsName);

		// the size of the cell data as indicated by the integer in the file
		off_t cellSize = -1;

		// the offset from the file offset to the start of the data section
		int dataOffset = -1;

		// get file fd
		std::string fileName = path + "/" + table + "/" + row + ".txt";
		if (verbose)
			std::cerr << "GetRow On Disk: File name: " << fileName << "\n";

		int fd = open(fileName.c_str(), O_RDONLY);

		// move to the file offset + 32 bytes for column key + 1 byte for space
		lseek(fd, fileOffset + 33, SEEK_SET);

		char sizeBuffer[32];
		read(fd, sizeBuffer, 32);

		// find space
		int spaceIndex = 0;
		while (spaceIndex < 32)
		{
			if (sizeBuffer[spaceIndex] == ' ')
			{
				break;
			}
			spaceIndex++;
		}

		// set up the offsets
		dataOffset = 33 + spaceIndex + 1;
		std::string sizeStr(sizeBuffer, spaceIndex);
		printf("2536: sizeStr: %s\n", sizeStr.c_str());
		cellSize = (off_t)std::stoul(sizeStr);

		lseek(fd, fileOffset + dataOffset, SEEK_SET);
		char contentBuffer[cellSize];
		read(fd, contentBuffer, cellSize);
		std::string contentStr(contentBuffer);

		size_t start = 0;
    	size_t end = 0;
		std::string currColumn;
		while ((end = contentStr.find('\n', start)) != std::string::npos)
		{
			currColumn = contentStr.substr(start, end - start);
			if (deletedColumns.find(currColumn) == deletedColumns.end())
			{
				columns.insert(currColumn);
			}
			start = end + 1;
		}

		close(fd);
		pthread_mutex_unlock(currLock);
	}

	std::string columnsStr;
	for (auto it = columns.begin(); it != columns.end(); it++)
	{
		columnsStr += *it;
		if (std::next(it) != columns.end())
		{
			columnsStr += "\n";
		}
	}

	const char *columnsBuffer = columnsStr.c_str();
	int columnsLength = columnsStr.size();

	bool done = false;

	// the offset within the columns Buffer
	off_t cellOffset = 0;

	while (!done)
	{
		std::vector<char> rspBuffer;
		if (cellOffset + CONTENTLENGTH >= columnsLength)
		{
			// done
			done = true;
			if (cellOffset == 0)
			{
				// first
				backendMessage rspMsg = backendMessage(backendMessage::Rsp,
													   msgIds[index], 1);
				rspMsg.setRspMsg(backendMessage::responseType::OK, std::string(columnsBuffer));
				rspMsg.serialize(rspBuffer);
			}
			else
			{
				// recurring
				backendMessage rspMsg = backendMessage(
					backendMessage::Append, msgIds[index], 1);
				rspMsg.setAppendMsg(table, row, allColumnsName, std::string(columnsBuffer, columnsLength - cellOffset));
				rspMsg.serialize(rspBuffer);
			}
		}
		else
		{
			// not done
			if (cellOffset == 0)
			{
				// first
				backendMessage rspMsg = backendMessage(backendMessage::Rsp,
													   msgIds[index], 0);
				rspMsg.setRspMsg(backendMessage::responseType::OK,
								 std::string(columnsBuffer, CONTENTLENGTH));
				rspMsg.serialize(rspBuffer);
			}
			else
			{
				// recurring
				backendMessage rspMsg = backendMessage(
					backendMessage::Append, msgIds[index], 0);
				rspMsg.setAppendMsg(table, row, allColumnsName,
									std::string(columnsBuffer + cellOffset, CONTENTLENGTH));
				rspMsg.serialize(rspBuffer);
			}
			cellOffset += CONTENTLENGTH;
		}
		write(fds[index], rspBuffer.data(), rspBuffer.size());
	}
}

/*
 * A function that handle a notify message
 * Input: reqType, the type of the original request
 * 		  sourceIpPort, the ip:port of the client for the original request
 * 		  table, the name of the table
 * 		  row, the row of the cell
 * 		  col, the column of the cell
 * 		  val, the val to put into the cell
 * 		  commFd, the fd to send back the response
 * 		  index, the thread index
 */
void notify(backendMessage::requestType reqType, std::string sourceIpPort,
			std::string table, std::string row, std::string col, std::string rawCol, std::string val,
			int end, int commFd, int index, off_t logOffset)
{
	printTime();
	if (verbose)
	{
		std::cout << "------------------------------------------------------\n";
		std::cout << "notify fd: " << commFd << "\n";
		std::cout << "notify table: " << table << "\n";
		std::cout << "notify row: " << row << "\n";
		std::cout << "notify column: " << col << "\n";
		std::cout << "notify val: " << val << "\n";
		std::cout << "notify raw col: " << rawCol << "\n";
	}

	if (groupRole == "primary")
	{
		if (verbose)
			std::cout << "primary notify secondaries\n";
		msgId2SourceIpPort[msgIds[index]] = sourceIpPort;

		// forward to all the secondaries
		backendMessage notifyMsg = backendMessage(backendMessage::Notify,
												  msgIds[index], 1);
		notifyMsg.setNotifyMsg(msgIds[index], reqType, "", table, row, rawCol,
							   val);
		for (std::string secondaryIpPort : secondaryIpPorts)
		{
			forwardToPeers(notifyMsg, secondaryIpPort);
		}
	}

	// process
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *currTable =
		&userTable;
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks =
		&userTableLocks;
	std::map<std::string, std::map<std::string, uint64_t>> *currOffsets =
		&userOffsets;
	pthread_mutex_t *currLock = &userOffsetLock;
	std::map<std::string, std::set<std::tuple<std::string, int>>> *currRawCols = &userRawCols;
	std::map<std::string, pthread_mutex_t> *currRawColsLocks = &userRawColsLocks;

	bool failed = false;

	if (table == "UserInfoTable")
	{
		currTable = &userTable;
		currTableLocks = &userTableLocks;
		currOffsets = &userOffsets;
		currLock = &userOffsetLock;
		currRawCols = &userRawCols;
		currRawColsLocks = &userRawColsLocks;
	}
	else if (table == "UserFileTable")
	{
		currTable = &fileTable;
		currTableLocks = &fileTableLocks;
		currOffsets = &fileOffsets;
		currLock = &fileOffsetLock;
		currRawCols = &fileRawCols;
		currRawColsLocks = &fileRawColsLocks;
	}
	else if (table == "InboxTable")
	{
		currTable = &inboxTable;
		currTableLocks = &inboxTableLocks;
		currOffsets = &inboxOffsets;
		currLock = &inboxOffsetLock;
		currRawCols = &inboxRawCols;
		currRawColsLocks = &inboxRawColsLocks;
	}

	if (verbose)
		std::cout << "Notify finished fiding table\n";

	if (reqType == backendMessage::requestType::PUT)
	{
		// write the put
		if (verbose)
			std::cout << "Notify PUT\n";
		putToTable(currTable, currTableLocks, currRawCols, currRawColsLocks, row, col, rawCol, val, end, false,
				   logOffset);
	}
	else if (reqType == backendMessage::requestType::DELETE)
	{
		// write the delete
		if (verbose)
			std::cout << "Notify DELETE\n";
		if (checkDeleteCond(currTable, currOffsets, currLock, currTableLocks,
							table, row, col) == "OK")
		{
			deleteOperation(currTable, currOffsets, &userOffsetLock,
							currTableLocks, currRawCols, currRawColsLocks, table, row, col, rawCol, logOffset);
		}
		else
		{
			// TODO: handle delete fail
		}
	}
	else
	{
		// append
		// write the append
		if (verbose)
			std::cout << "Notify APPEND\n";
		pthread_mutex_lock(&currTableLocks->at(row).at(col));
		std::string newVal = std::get<3>(currTable->at(row)[col]) + val;
		currTable->at(row)[col] = std::make_tuple("add", end, logOffset,
												  newVal);
		tablesSize += val.size();
		pthread_mutex_unlock(&currTableLocks->at(row).at(col));
		// putToTable(currTable, currTableLocks, currRawCols, currRawColsLocks, row, col, rawCol, val, end, true,
		// 		   logOffset);
	}

	if (groupRole == "primary")
	{
		if (counterLocks.find(msgIds[index]) == counterLocks.end())
		{
			// msgIds[index] not in counterLocks
			pthread_mutex_t newLock;
			pthread_mutex_init(&newLock, NULL);
			counterLocks.insert({msgIds[index], newLock});
		}
		pthread_mutex_lock(&counterLocks[msgIds[index]]);
		if (ackCounter.find(msgIds[index]) == ackCounter.end())
		{
			ackCounter[msgIds[index]] = 1;
		}
		else
		{
			ackCounter[msgIds[index]]++;
			if (ackCounter[msgIds[index]] == secondaryIpPorts.size() + 1)
			{
				deliverRsp(index);
			}
		}
		pthread_mutex_unlock(&counterLocks[msgIds[index]]);
	}
	else
	{
		// secondary
		// notify ack to primary
		backendMessage ackMsg = backendMessage(backendMessage::Ack,
											   msgIds[index], 1);
		if (failed)
		{
			ackMsg.setAckMsg(msgIds[index], backendMessage::responseType::ERR);
		}
		else
		{
			ackMsg.setAckMsg(msgIds[index], backendMessage::responseType::OK);
		}
		forwardToPeers(ackMsg, primaryIpPort);
		std::cout << "Notify ack to primary done\n";
	}
}

/*
 * A function that handle an ACK message
 * Input: reqId, the ID of the original request
 * 		  status, the status of the original request
 * 		  commFd, the fd to send back the response
 * 		  index, the thread index
 */
void ack(std::string reqId, backendMessage::responseType status, int commFd,
		 int index)
{
	std::cout << "msgId2SourceIpPort[msgId]1: "
			  << (msgId2SourceIpPort.find(msgIds[index]) == msgId2SourceIpPort.end()) << std::endl;
	if (verbose)
	{
		std::cout << "------------------------------------------------------\n";
		std::cout << "ack fd: " << commFd << "\n";
		std::cout << "ack status: " << status << "\n";
		std::cout << "ack reqId: " << reqId << "\n";
	}

	if (groupRole == "primary")
	{
		if (status == backendMessage::responseType::OK)
		{
			if (counterLocks.find(msgIds[index]) == counterLocks.end())
			{
				// msgIds[index] not in counterLocks
				if (verbose)
					std::cout << "msgIds[index] not in counterLocks\n";
				pthread_mutex_t newLock;
				pthread_mutex_init(&newLock, NULL);
				counterLocks.insert({msgIds[index], newLock});
			}
			pthread_mutex_lock(&counterLocks[msgIds[index]]);
			if (ackCounter.find(msgIds[index]) == ackCounter.end())
			{
				if (verbose)
					std::cout << "ackCounter[msgIds[index]] not in ackCounter\n";
				ackCounter[msgIds[index]] = 1;
			}
			else
			{
				std::cout << "ACK: ackCounter before increment: "
						  << ackCounter[msgIds[index]] << "\n";
				ackCounter[msgIds[index]]++;
			}
			pthread_mutex_unlock(&counterLocks[msgIds[index]]);
		}
		else
		{
			// failed
			// TODO: check later
			return;
		}

		pthread_mutex_lock(&counterLocks[msgIds[index]]);
		if (ackCounter[msgIds[index]] == secondariesReady + 1)
		{
			if (verbose)
				std::cout << "Ack ready to deliver\n";
			deliverRsp(index);
		}
		pthread_mutex_unlock(&counterLocks[msgIds[index]]);
	}
	else
	{
		// secondary
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		if (status == backendMessage::responseType::OK)
		{
			if (verbose)
				std::cout << "Secondary received Ack OK\n";
			rspMsg.setRspMsg(backendMessage::responseType::OK,
							 "Command implemented");
		}
		else
		{
			if (verbose)
				std::cout << "Secondary received Ack ERR\n";
			rspMsg.setRspMsg(backendMessage::responseType::ERR,
							 "Failed to implement command");
		}
		rspMsg.serialize(rspBuffer);
		write(msgId2ClientFd[msgIds[index]], rspBuffer.data(),
			  rspBuffer.size());
		if (verbose)
			std::cout << "ack done\n";
		cleanUpMsgIdMaps(msgIds[index]);
	}
}

/*
 * A function to write the inMemTable to the disk and update the offsetTable
 * Input: inMemTable, the in-memory table
 * 		  offsetTable, the offset table
 * 		  tableLocks, the table locks
 * 		  table, the name of the table
 * Output: true if success, false if fail
 */
bool writeToDisk(
	std::map<std::string,
			 std::map<std::string,
					  std::tuple<std::string, int, off_t, std::string>>> *
		inMemTable,
	std::map<std::string, std::map<std::string, uint64_t>> *offsetTable,
	std::map<std::string, std::set<std::tuple<std::string, int>>> *rawCols,
	std::map<std::string, std::map<std::string, pthread_mutex_t>> *tableLocks,
	std::string table)
{
	if (verbose)
	{
		printf("Starting write to disk for table %s\n", table.c_str());
	}
	std::string tablePath = path + "/" + table;
	for (const auto &entry : fs::directory_iterator(tablePath))
	{
		std::string rowName = entry.path().filename().string().substr(0, entry.path().filename().string().size() - 4);
		if (inMemTable->find(rowName) == inMemTable->end())
		{
			// row not modified
			continue;
		}
		off_t cellOffset = 0;
		std::string colName;
		std::string cellContent;
		std::string allCols;
		std::set<std::tuple<std::string, int>> allColsSet = rawCols->at(rowName);
		std::vector<std::string> deletedCols;
		bool toDelete = false;
		for (auto it = allColsSet.begin(); it != allColsSet.end(); it++)
		{
			if (std::get<1>(*it) == 1)
			{
				allCols += std::get<0>(*it).c_str();
				allCols += "\n";
			} else {
				deletedCols.push_back(std::get<0>(*it));
			}
		}
		std::string newFilePath = tablePath + "/" + rowName + "-new.txt";
		int newFd = open(newFilePath.c_str(), O_CREAT | O_RDWR | O_APPEND, 0777);
		if (newFd < 0)
		{
			fs::remove(newFilePath);
			printf("WriteToDisk: Cannot open file %s: %s\n", (tablePath + "/" + rowName + "-new.txt").c_str(), strerror(errno));
			printf("Fail to write to disk for row %s in table %s\n", rowName.c_str(), table.c_str());
			return false;
		}

		std::string oldFilePath = tablePath + "/" + rowName + ".txt";
		if (fs::exists(oldFilePath))
		{
			int oldFd = open(oldFilePath.c_str(), O_RDONLY);
			if (oldFd < 0)
			{
				close(newFd);
				printf("WriteToDisk: Cannot open file %s: %s\n", oldFilePath.c_str(), strerror(errno));
				printf("Fail to write to disk for row %s in table %s\n", rowName.c_str(), table.c_str());
				return false;
			}

			off_t oldFileSize = lseek(oldFd, 0, SEEK_END);
			off_t currOffset = 0;
			while (currOffset < oldFileSize)
			{
				// read column name
				lseek(oldFd, currOffset, SEEK_SET);
				char colBuffer[32];
				int readBytes = read(oldFd, colBuffer, 32);
				if (readBytes < 0 || readBytes != 32)
				{
					close(newFd);
					close(oldFd);
					printf("WriteToDisk: Cannot read file %s: %s\n", (tablePath + "/" + rowName + ".txt").c_str(), strerror(errno));
					return false;
				}
				colName = std::string(colBuffer, 32);

				// read cell size
				currOffset += 33;
				lseek(oldFd, currOffset, SEEK_SET);
				char sizeBuffer[32];
				int spaceIndex = 0;
				if (read(oldFd, sizeBuffer, 32) < 0)
				{
					close(newFd);
					close(oldFd);
					printf("Fail to read from file %s: %s\n", (tablePath + "/" + rowName + ".txt").c_str(), strerror(errno));
					printf("Fail to write to disk for column %s in table %s\n", colName.c_str(), table.c_str());
					return false;
				}
				while (spaceIndex < 32)
				{
					if (sizeBuffer[spaceIndex] == ' ')
					{
						break;
					}
					spaceIndex++;
				}
				printf("currOffset: %ld\n", currOffset);
				printf("sizeBuffer: %s\n", sizeBuffer);
				std::string sizeStr(sizeBuffer, spaceIndex);
				printf("sizeStr: %s\n", sizeStr.c_str());
				printf("spaceIndex: %d\n", spaceIndex);
				off_t cellSize = (off_t)std::stoul(sizeStr);

				if (colName == allColumnsName) {
					currOffset += spaceIndex + 1;
					lseek(oldFd, currOffset, SEEK_SET);
					char contentBuffer[cellSize];
					readBytes = read(oldFd, contentBuffer, cellSize);
					if (readBytes < 0 || readBytes != cellSize)
					{
						close(newFd);
						close(oldFd);
						printf("3015: Fail to read from file %s: %s\n", (tablePath + "/" + rowName + ".txt").c_str(), strerror(errno));
						printf("Fail to write to disk for column %s in table %s\n", colName.c_str(), table.c_str());
						return false;
					}
					std::string contentStr(contentBuffer, cellSize);
					size_t start = 0;
					size_t end = 0;
					while ((end = contentStr.find('\n', start)) != std::string::npos) {
						std::string currCol = contentStr.substr(start, end - start);
						if (allCols.find(currCol) == std::string::npos &&
							std::find(deletedCols.begin(), deletedCols.end(), currCol) == deletedCols.end()) {
							allCols += currCol + "\n";
						}
						start = end + 1;
					}
					currOffset += cellSize;
				} else {
					if (inMemTable->at(rowName).find(colName) == inMemTable->at(rowName).end() || std::get<1>(inMemTable->at(rowName).at(colName)) == 0)
					{
						// data not modified or modification not finished, copy old data to new file
						if (verbose) {
							printf("Copying old data for column %s in table %s\n", colName.c_str(), table.c_str());
						}
						currOffset += spaceIndex + 1;
						lseek(oldFd, currOffset, SEEK_SET);
						char contentBuffer[cellSize];
						int readBytes = read(oldFd, contentBuffer, cellSize);
						if (readBytes < 0 || readBytes != cellSize)
						{
							close(newFd);
							close(oldFd);
							printf("Fail to read from file %s: %s\n", (tablePath + "/" + rowName + ".txt").c_str(), strerror(errno));
							printf("Fail to write to disk for column %s in table %s\n", colName.c_str(), table.c_str());
							return false;
						}
						std::string contentStr(contentBuffer, cellSize);
						cellContent = colName + " " + std::to_string(cellSize) + " " + contentStr;
						if (write(newFd, cellContent.c_str(), cellContent.size()) < 0)
						{
							close(newFd);
							close(oldFd);
							printf("Fail to write to file %s: %s\n", (tablePath + "/" + rowName + "-new.txt").c_str(), strerror(errno));
							printf("Fail to write to disk for column %s in table %s\n", colName.c_str(), table.c_str());
							return false;
						}
						currOffset += cellSize;
					}
					else
					{
						// data modified, write new data to new file
						if (verbose) {
							printf("Writing new data for column %s in table %s\n", colName.c_str(), table.c_str());
						}
						std::string cellCmd = std::get<0>(inMemTable->at(rowName).at(colName));
						if (cellCmd != "delete")
						{
							// write new data to new file if the operation is finishe
							std::string cellVal = std::get<3>(inMemTable->at(rowName).at(colName));
							cellContent = colName + " " + std::to_string(static_cast<uint32_t>(cellVal.size())) + " " + cellVal;
							if (write(newFd, cellContent.c_str(), cellContent.size()) < 0)
							{
								close(newFd);
								close(oldFd);
								printf("Fail to write to file %s: %s\n", (tablePath + "/" + rowName + "-new.txt").c_str(), strerror(errno));
								printf("Fail to write to disk for column %s in table %s\n", colName.c_str(), table.c_str());
								return false;
							}
						} else {
							rawCols->at(rowName).erase({colName, 0});
							toDelete = true;
						}
						currOffset += spaceIndex + 1 + cellSize;
						inMemTable->at(rowName).erase(colName);
						tableLocks->at(rowName).erase(colName);
					}
					// update offsetTable
					if (!toDelete)
					{ 
						if (offsetTable->find(rowName) == offsetTable->end())
						{
							offsetTable->insert({rowName, {}});
						}
						offsetTable->at(rowName)[colName] = cellOffset;
						if (verbose)
						{
							printf("3114: rowName: %s, colName: %s, cellOffset: %ld\n", rowName.c_str(), colName.c_str(), offsetTable->at(rowName)[colName]);
						}
					} else {
						offsetTable->at(rowName).erase(colName);
						if (verbose)
						{
							printf("Deleted rowName: %s, colName: %s\n", rowName.c_str(), colName.c_str());
						}
					}
				}
				if (!toDelete) {
					cellOffset += cellContent.size();
				}

			}
			close(oldFd);
		}

		// write new data for the current row to new file
		for (auto it = inMemTable->begin(); it != inMemTable->end();)
		{
			std::string currRow = it->first;
			if (currRow != rowName)
			{
				++it;
				continue;
			}
			for (auto it2 = inMemTable->at(rowName).begin(); it2 != inMemTable->at(rowName).end();)
			{
				colName = it2->first;
				std::string cellCmd = std::get<0>(it2->second);
				if (cellCmd == "delete")
				{
					rawCols->at(rowName).erase({colName, 0});
					it2 = inMemTable->at(rowName).erase(it2);
					tableLocks->at(rowName).erase(colName);
				} else if (std::get<1>(it2->second) == 1)
				{
					// write new data to new file if the operation is finished
					std::string cellVal = std::get<3>(it2->second);
					cellContent = colName + " " + std::to_string(static_cast<uint32_t>(cellVal.size())) + " " + cellVal;
					if (write(newFd, cellContent.c_str(), cellContent.size()) < 0)
					{
						fs::remove(newFilePath);
						close(newFd);
						printf("Fail to write to file %s: %s\n", (tablePath + "/" + rowName + "-new.txt").c_str(), strerror(errno));
						printf("Fail to write to disk for column %s in table %s\n", colName.c_str(), table.c_str());
						return false;
					}
					if (offsetTable->find(rowName) == offsetTable->end())
					{
						offsetTable->insert({rowName, {}});
					}
					offsetTable->at(rowName)[colName] = cellOffset;
					if (verbose)
					{
						printf("3167: rowName: %s, colName: %s, cellOffset: %ld\n", rowName.c_str(), colName.c_str(), offsetTable->at(rowName)[colName]);
					}
					cellOffset += cellContent.size();
					it2 = inMemTable->at(rowName).erase(it2);
					tableLocks->at(rowName).erase(colName);
				}
				else
				{
					++it2;
				}
			}
			if (inMemTable->at(rowName).size() == 0)
			{
				it = inMemTable->erase(it);
				tableLocks->erase(rowName);
			}
			else
			{
				++it;
			}
		}
		std::string allColsContent = allColumnsName + " " + std::to_string(static_cast<uint32_t>(allCols.size())) + " " + allCols;
		if (write(newFd, allColsContent.c_str(), allColsContent.size()) < 0)
		{
			close(newFd);
			printf("Fail to write to file %s: %s\n", (tablePath + "/" + rowName + "-new.txt").c_str(), strerror(errno));
			printf("Fail to write to disk for row %s in table %s\n", rowName.c_str(), table.c_str());
			return false;
		}
		offsetTable->at(rowName)[allColumnsName] = cellOffset;
		close(newFd);

		// remove old file and rename new file
		try
		{
			if (fs::exists(oldFilePath))
			{
				fs::remove(oldFilePath);
			}
			fs::rename(newFilePath, oldFilePath);
		}
		catch (fs::filesystem_error &e)
		{
			printf("Fail to remove file %s: %s\n", oldFilePath.c_str(), e.what());
		}
	}

	// write for new rows
	for (auto it = inMemTable->begin(); it != inMemTable->end();)
	{
		std::string rowName = it->first;
		if (offsetTable->find(rowName) != offsetTable->end())
		{
			continue;
		}
		std::string allCols;
		std::set<std::tuple<std::string, int>> allColsSet = rawCols->at(rowName);
		for (auto it2 = allColsSet.begin(); it2 != allColsSet.end(); it2++)
		{
			if (std::get<1>(*it2) == 1)
			{
				allCols += std::get<0>(*it2);
				allCols += "\n";
			}
		}
		std::string fileName = path + "/" + table + "/" + rowName + ".txt";
		if (verbose)
		{
			printf("Writing to file %s\n", fileName.c_str());
		}
		int fileFd = open(fileName.c_str(), O_CREAT | O_RDWR | O_APPEND, 0777);
		if (fileFd < 0)
		{
			printf("WriteToDisk: Cannot open file %s: %s\n", fileName.c_str(), strerror(errno));
			printf("Fail to write to disk for row %s in table %s\n", rowName.c_str(), table.c_str());
			return false;
		}
		off_t currOffset = 0;
		for (auto it2 = inMemTable->at(rowName).begin(); it2 != inMemTable->at(rowName).end();)
		{
			std::string colName = it2->first;
			std::string cellCmd = std::get<0>(it2->second);
			int isEnd = std::get<1>(it2->second);
			if (cellCmd == "delete")
			{
				rawCols->at(rowName).erase({colName, 0});
				it2 = inMemTable->at(rowName).erase(it2);
			} else if (isEnd == 0)
			{
				it2++;
			} else {
				std::string cellVal = std::get<3>(it2->second);
				std::string cellContent = colName + " " + std::to_string(static_cast<uint32_t>(cellVal.size())) + " " + cellVal;
				if (write(fileFd, cellContent.c_str(), cellContent.size()) < 0)
				{
					close(fileFd);
					printf("Fail to write to file %s: %s\n", fileName.c_str(), strerror(errno));
					printf("Fail to write to disk for column %s in table %s\n", colName.c_str(), table.c_str());
					return false;
				}
				if (offsetTable->find(rowName) == offsetTable->end())
				{
					offsetTable->insert({rowName, {}});
				}
				offsetTable->at(rowName)[colName] = currOffset;
				currOffset += cellContent.size();
				it2 = inMemTable->at(rowName).erase(it2);
			}
		}
		if (inMemTable->at(rowName).size() == 0)
		{
			it = inMemTable->erase(it);
		}
		else
		{
			++it;
		}
		std::string allColsContent = allColumnsName + " " + std::to_string(static_cast<uint32_t>(allCols.size())) + " " + allCols;
		if (write(fileFd, allColsContent.c_str(), allColsContent.size()) < 0)
		{
			close(fileFd);
			printf("Fail to write to file %s: %s\n", fileName.c_str(), strerror(errno));
			printf("Fail to write to disk for row %s in table %s\n", rowName.c_str(), table.c_str());
			return false;
		}
		offsetTable->at(rowName)[allColumnsName] = currOffset;
		close(fileFd);
	}

	if (verbose)
	{
		printf("Write to disk for table %s done\n", table.c_str());
		printf("inMemTable size after checkpoint: %ld\n", inMemTable->size());
	}
	return true;
}

/*
 * A function to find log file for recovery.
 * Return: a vector of strings containing the file paths of the log files
 */

std::vector<std::string> findLogFiles()
{
	std::vector<std::string> logFiles;
	bool logFileFound = false;
	for (const auto &entry : fs::directory_iterator(path))
	{
		std::string filePath = entry.path().filename().string();
		if (filePath.find("log") != std::string::npos)
		{
			logFiles.push_back(filePath);
			logFileFound = true;
		}
	}

	if (logFiles.size() > 3)
	{
		fprintf(stderr, "Error: More than 3 log files found\n");
	}

	std::string oldLogFilePath = "";
	std::string tmpLogFilePath = "";
	std::string newLogFilePath = "";
	if (logFiles.size() != 0)
	{
		for (std::string logFileName : logFiles)
		{
			std::string currLogFilePath = path + "/" + logFileName;
			if (isdigit(logFileName[3]))
			{
				uint32_t currCPVersion = std::stoul(
					logFileName.substr(3, logFileName.length()));
				if (currCPVersion >= cpVersion)
				{
					oldLogFilePath = newLogFilePath;
					cpVersion = currCPVersion;
					logFilePath = currLogFilePath;
					newLogFilePath = currLogFilePath;
				}
				else
				{
					oldLogFilePath = currLogFilePath;
				}
			}
			else if (logFileName.find("Tmp") != std::string::npos)
			{
				tmpLogFilePath = currLogFilePath;
			}
			else
			{
				fprintf(stderr, "Error: Unexpected log file name: %s\n", logFileName.c_str());
			}
		}
		if (verbose)
		{
			printf("Latest local log file: %s\n", logFilePath.c_str());
			printf("cpVersion: %d\n", cpVersion);
		}
	}
	else
	{
		logFilePath = path + "/log0.txt";
		int fd = open(logFilePath.c_str(), O_CREAT | O_RDWR | O_APPEND, 0777);
		if (fd < 0)
		{
			printf("findLogFiles: File to create log file %s: %s\n",
				   logFilePath.c_str(), strerror(errno));
			return logFiles;
		}
		close(fd);
		newLogFilePath = logFilePath;
		cpVersion = 0;
		if (verbose)
		{
			printf("No local log file found, creating one with version 0\n");
		}
	}

	logFiles.clear();
	logFiles.push_back(oldLogFilePath);
	logFiles.push_back(tmpLogFilePath);
	logFiles.push_back(newLogFilePath);

	if (verbose)
	{
		printf("Old log file: %s\n", oldLogFilePath.c_str());
		printf("Tmp log file: %s\n", tmpLogFilePath.c_str());
		printf("New log file: %s\n", newLogFilePath.c_str());
	}

	return logFiles;
}

/*
 * A function that logs a request into the disk
 * Input: request, the request message
 */
off_t logRequest(backendMessage request)
{
	// check if is checkpointing
	std::string currFilePath = logFilePath;
	if (isCheckpointing)
	{
		currFilePath = path + "/logTmp.txt";
	}
	if (verbose)
	{
		printf("Logging request to file %s\n", currFilePath.c_str());
	}

	pthread_mutex_lock(&logFileMutex);
	isLogging = true;
	int logFd = open(currFilePath.c_str(), O_CREAT | O_RDWR | O_APPEND, 0777);
	if (logFd < 0)
	{
		pthread_mutex_unlock(&logFileMutex);
		printf("logRequest: Cannot open log file %s: %s\n",
			   currFilePath.c_str(), strerror(errno));
		return -1;
	}
	off_t offset = lseek(logFd, 0, SEEK_END);
	std::vector<char> buffer;
	request.serialize(buffer);
	if (write(logFd, buffer.data(), buffer.size()) < 0)
	{
		printf("Fail to write to log file %s: %s\n", currFilePath.c_str(),
			   strerror(errno));
		return -1;
	}
	close(logFd);
	isLogging = false;
	pthread_mutex_unlock(&logFileMutex);
	return offset;
}

/*
 * A function that performs a request
 * Input: request, the request message
 * 		  commFd, the fd to send back the response
 * 		  index, the thread index
 */
void performRequest(backendMessage request, int commFd, int index,
					off_t logOffset)
{
	printf("Performing request: Message Type %d\n", request.msgType);
	if (request.msgType == backendMessage::Req)
	{
		// request
		backendMessage::ReqMsg reqMsg = request.getReqMsg();
		if (verbose)
		{
			std::cout << "Table name: " << reqMsg.tableName << "\n";
		}
		if (reqMsg.reqType == backendMessage::requestType::GET)
		{
			// get
			get(reqMsg.tableName, computeDigest(reqMsg.rowName),
				computeDigest(reqMsg.colName), commFd, index);
		}
		else if (reqMsg.reqType == backendMessage::requestType::PUT)
		{
			// put
			if (tablesSize + reqMsg.newVal.size() > MEMLIMIT)
			{
				// initiate a checkpoint
				std::vector<char> cpBuffer;
				backendMessage cpMsg = backendMessage(backendMessage::CP,
													  msgIds[index], 1);
				cpMsg.setCPMsg(0);
				cpMsg.serialize(cpBuffer);
				write(coordSocket, cpBuffer.data(), cpBuffer.size());
			}

			put(reqMsg.tableName, computeDigest(reqMsg.rowName),
				computeDigest(reqMsg.colName), reqMsg.colName, reqMsg.newVal, commFd, index,
				request.isEnd, logOffset);
		}
		else if (reqMsg.reqType == backendMessage::requestType::CPUT)
		{
			// cput
			if (tablesSize + reqMsg.newVal.size() - reqMsg.matchVal.size() > MEMLIMIT)
			{
				// initiate a checkpoint
				std::vector<char> cpBuffer;
				backendMessage cpMsg = backendMessage(backendMessage::CP,
													  msgIds[index], 1);
				cpMsg.setCPMsg(0);
				cpMsg.serialize(cpBuffer);
				write(coordSocket, cpBuffer.data(), cpBuffer.size());
			}
			cPut(reqMsg.tableName, computeDigest(reqMsg.rowName),
				 computeDigest(reqMsg.colName), reqMsg.colName, reqMsg.matchVal,
				 reqMsg.newVal, commFd, index, request.isEnd, logOffset);
		}
		else if (reqMsg.reqType == backendMessage::requestType::VERIFY)
		{
			// verify
			verify(computeDigest(reqMsg.rowName), reqMsg.matchVal, commFd, index);
		}
		else if (reqMsg.reqType == backendMessage::requestType::GETROW)
		{
			// get row
			getRow(reqMsg.tableName, computeDigest(reqMsg.rowName), commFd, index);
		}
		else
		{
			// delete
			deleteCell(reqMsg.tableName, computeDigest(reqMsg.rowName),
					   computeDigest(reqMsg.colName), reqMsg.colName, commFd, index, logOffset);
		}
	}
	else if (request.msgType == backendMessage::CP)
	{
		if (lastCPSuccess)
		{
			backendMessage cpAckMsg = backendMessage(backendMessage::CPAck, "", 1);
			cpAckMsg.setCPAckMsg(backendMessage::responseType::OK);
			std::vector<char> buffer;
			cpAckMsg.serialize(buffer);
			write(coordSocket, buffer.data(), buffer.size());
		}
		else
		{
			if (cpVersion == request.getCPMsg().cpVersion - 1)
			{
				cpVersion++;
				if (verbose)
				{
					printf("Secondary: Checkpointing version #%d\n", cpVersion);
				}
				std::vector<char> buffer;
				backendMessage cpAckMsg = backendMessage(backendMessage::CPAck,
														 request.msgId, 1);
				if (doCheckpoint())
				{
					// successfully checkpointed
					cpAckMsg.setCPAckMsg(backendMessage::responseType::OK);
					lastCPSuccess = true;
				}
				else
				{
					// failed to checkpoint
					cpAckMsg.setCPAckMsg(backendMessage::responseType::ERR);
				}

				cpAckMsg.serialize(buffer);
				write(commFd, buffer.data(), buffer.size());
				if (verbose)
				{
					printf("Secondary: Sent CPACK to primary\n");
				}
			}
			else
			{
				// TODO: not the synchronized version, ask primary for actual data and log file
			}
		}
	}
	else if (request.msgType == backendMessage::CPAck)
	{
		if (groupRole == "primary")
		{
			bool cpFinished = false;
			if (request.getCPAckMsg().status == backendMessage::responseType::OK)
			{
				pthread_mutex_lock(&cpMutex);
				numCPFinished++;
				cpFinished = numCPFinished == secondaryIpPorts.size() + 1;
				pthread_mutex_unlock(&cpMutex);
			}
			else
			{
				// TODO: handle the case that checkpoint has failed
			}
			if (!cpFinished)
				return;
			// all workers have finished checkpointing, send ack to everyone to resume working
			std::vector<char> buffer;
			backendMessage cpAckMsg = backendMessage(backendMessage::CPAck, "",
													 1);
			cpAckMsg.setCPAckMsg(backendMessage::responseType::OK);
			cpAckMsg.serialize(buffer);
			for (auto it = secondaryIpPorts.begin();
				 it != secondaryIpPorts.end(); it++)
			{
				forwardToPeers(cpAckMsg, *it);
			}
			if (verbose)
			{
				printf("Primary: Checkpointing finished for version #%d\n", cpVersion);
			}
			clearQueue();
			lastCPSuccess = false;
			numCPFinished = 0;
		}
		else if (groupRole == "secondary")
		{
			if (request.getCPAckMsg().status == backendMessage::responseType::OK)
			{
				if (verbose)
				{
					printf("Secondary: Checkpointing finished for version #%d\n", cpVersion);
				}
				clearQueue();
				lastCPSuccess = false;
			}
			else
			{
				// TODO: handle the case that checkpoint has failed
			}
		}
		else
		{
			fprintf(stderr, "Error: CPACK received by unassigned worker\n");
		}
	}
	else if (request.msgType == backendMessage::Notify)
	{
		// notify for write operations
		backendMessage::NotifyMsg notifyMsg = request.getNotifyMsg();
		notify(notifyMsg.reqType, notifyMsg.sourceId, notifyMsg.tableName,
			   notifyMsg.rowName, computeDigest(notifyMsg.colName), notifyMsg.colName, notifyMsg.newVal,
			   request.isEnd, commFd, index, logOffset);
	}
	else if (request.msgType == backendMessage::Ack)
	{
		// ack about finished writings
		backendMessage::AckMsg ackMsg = request.getAckMsg();
		ack(ackMsg.reqId, ackMsg.status, commFd, index);
	}
	else if (request.msgType == backendMessage::Shutdown)
	{
		if (verbose)
		{
			std::cout << "Worker " << index << " received shutdown message" << std::endl;
		}
		while (isLogging) {}
		pretend = true;
		groupRole = "unassigned";
		// pretend shutdown
		// close the fds
		for (int i = 0; i < NUMTHREADS; i++)
		{
			if (i != index && fds[i] != 0)
			{
				close(fds[i]);
				fds[i] = 0;
			}
		}

		if (verbose) {
			std::cout << "Shutdown fds closed" << std::endl;
		}

		for (int i = 0; i < NUMTHREADS; i++)
		{
			if (verbose) {
				std::cout << "Shutting down thread " << i << " , value: " << threads[i] << std::endl;
			}
			if (i != index && threads[i] != 0)
			{
				if (verbose) {
					std::cout << "Thread at index i needs to be joined" << std::endl;
				}
				// pthread_cancel(threads[i]);
				// pthread_join(threads[i], NULL);
				pthread_detach(threads[i]);
				threads[i] = 0;
				if (verbose) {
					std::cout << "Thread at index i joined" << std::endl;
				}
			}
		}

		if (verbose) {
			std::cout << "Shutdown threads joined" << std::endl;
		}

		pthread_cancel(pingThread);
		pthread_join(pingThread, NULL);
		pthread_cancel(coordThread);
		pthread_join(coordThread, NULL);

		if (verbose) {
			std::cout << "Shutdown coord and ping threads joined" << std::endl;
		}

		for (auto iter = userTableLocks.begin(); iter != userTableLocks.end();
			 iter++)
		{
			for (auto iter2 = iter->second.begin(); iter2 != iter->second.end();
				 iter2++)
			{
				pthread_mutex_destroy(&iter2->second);
			}
		}
		userTableLocks.clear();
		userTable.clear();
		userOffsets.clear();
		if (verbose) {
			std::cout << "Shutdown user table cleared" << std::endl;
		}

		for (auto iter = fileTableLocks.begin(); iter != fileTableLocks.end();
			 iter++)
		{
			for (auto iter2 = iter->second.begin(); iter2 != iter->second.end();
				 iter2++)
			{
				pthread_mutex_destroy(&iter2->second);
			}
		}
		fileTableLocks.clear();
		fileTable.clear();
		fileOffsets.clear();
		if (verbose) {
			std::cout << "Shutdown file table cleared" << std::endl;
		}

		for (auto iter = inboxTableLocks.begin(); iter != inboxTableLocks.end();
			 iter++)
		{
			for (auto iter2 = iter->second.begin(); iter2 != iter->second.end();
				 iter2++)
			{
				pthread_mutex_destroy(&iter2->second);
			}
		}
		inboxTableLocks.clear();
		inboxTable.clear();
		inboxOffsets.clear();
		if (verbose) {
			std::cout << "Shutdown inbox table cleared" << std::endl;
		}

		for (auto iter = fileRawColsLocks.begin(); iter != fileRawColsLocks.end(); iter++)
		{
			pthread_mutex_destroy(&iter->second);
		}
		fileRawColsLocks.clear();
		fileRawCols.clear();
		if (verbose) {
			std::cout << "Shutdown file raw table cleared" << std::endl;
		}

		for (auto iter = userRawColsLocks.begin(); iter != userRawColsLocks.end(); iter++)
		{
			pthread_mutex_destroy(&iter->second);
		}
		userRawColsLocks.clear();
		userRawCols.clear();
		if (verbose) {
			std::cout << "Shutdown user raw table cleared" << std::endl;
		}

		for (auto iter = inboxRawColsLocks.begin(); iter != inboxRawColsLocks.end(); iter++)
		{
			pthread_mutex_destroy(&iter->second);
		}
		inboxRawColsLocks.clear();
		inboxRawCols.clear();
		if (verbose) {
			std::cout << "Shutdown inbox raw table cleared" << std::endl;
		}

		tablesSize = 0;

		for (auto iter = counterLocks.begin(); iter != counterLocks.end(); iter++)
		{
			pthread_mutex_destroy(&iter->second);
		}
		counterLocks.clear();
		if (verbose) {
			std::cout << "Shutdown counter locks cleared" << std::endl;
		}

		shutdown(ownSocket, SHUT_RDWR);
		close(ownSocket);
		close(coordSocket);
		if (verbose)
		{
			std::cout << "Shutdown sockets closed" << std::endl;
			std::cout << "ownSocket after closing: " << ownSocket << std::endl;
		}

		pthread_mutex_destroy(&logFileMutex);
		pthread_mutex_destroy(&cpMutex);

		for (int i = 0; i < NUMTHREADS; i++)
		{
			if (i == index)
				continue;
			struct threadArgs *arg = args[i];
			if (arg != NULL)
			{
				free(arg);
				arg = NULL;
			}
			if (buffers[i] != NULL)
			{
				free(buffers[i]);
				buffers[i] = NULL;
			}
		}

		if (verbose)
		{
			std::cout << "Worker " << index << " shutdown done" << std::endl;
		}
	}
	else if (request.msgType == backendMessage::Restart)
	{
		// restart
		if (verbose)
		{
			std::cout << "Worker " << index << " received restart message" << std::endl;
		}
		pretend = false;
		// doRecovery();
	}
	else if (request.msgType == backendMessage::Append)
	{
		// append
		backendMessage::AppendMsg appendMsg = request.getAppendMsg();
		if (tablesSize + appendMsg.appendMsg.size() > MEMLIMIT)
		{
			// initiate a checkpoint
			std::vector<char> cpBuffer;
			backendMessage cpMsg = backendMessage(backendMessage::CP,
												  msgIds[index], 1);
			cpMsg.setCPMsg(0);
			cpMsg.serialize(cpBuffer);
			write(coordSocket, cpBuffer.data(), cpBuffer.size());
		}
		append(appendMsg.tableName, computeDigest(appendMsg.rowName),
			   computeDigest(appendMsg.colName), appendMsg.colName, appendMsg.appendMsg,
			   request.isEnd, logOffset, commFd, index);
	}
	else if (request.msgType == backendMessage::LogFileReq)
	{
		if (groupRole == "primary")
		{
			std::string workerIpPort = request.getLogFileReqMsg().workerId;
			backendMessage logFileMsg = backendMessage(
				backendMessage::LogFileRsp, request.msgId, 1);
			logFileMsg.setLogFileRspMsg(cpVersion);
			forwardToPeers(logFileMsg, workerIpPort);
			if (verbose)
			{
				printf("Primary: Log file response for cpVersion %d sent to secondary worker %s\n", cpVersion, workerIpPort.c_str());
			}
		}
		else
		{
			fprintf(stderr,
					"Error: Log file request sent to non-primary worker\n");
		}
	}
	else if (request.msgType == backendMessage::LogFileRsp)
	{
		uint32_t currCPVersion = request.getLogFileRspMsg().cpVersion;
		if (verbose)
		{
			printf("Log file response received for cpVersion %d\n", currCPVersion);
		}

		// recover from the local log file
		std::vector<std::string> logFiles = findLogFiles();
		std::string oldLogFile = logFiles[0];
		std::string tmpLogFile = logFiles[1];
		std::string newLogFile = logFiles[2];
		off_t offset;
		// if the cpVersion is the same, 2 cases
		// case1: has 1 log file, the most up-to-date one
		// case2: has 3 log files, the update for newlog file was not finished
		if (currCPVersion == cpVersion)
		{
			offset = recoverFromLocalLog(oldLogFile, tmpLogFile, newLogFile);
		}
		// 2 log files, the node crashed during checkpointing and cp was for the previous cpVersion
		else if (currCPVersion == cpVersion + 1 && oldLogFile == "" && tmpLogFile != "" && newLogFile != "")
		{
			offset = recoverFromLocalLog("", tmpLogFile, newLogFile);
		}
		else
		{
			// having outdated log files
			// delete outdated data/log files
			if (!rmOutdatedFiles(path + "/UserInfoTable"))
			{
				fprintf(stderr, "Error: Fail to remove outdated files in UserInfoTable\n");
				return;
			}
			else if (!rmOutdatedFiles(path + "/UserFileTable"))
			{
				fprintf(stderr, "Error: Fail to remove outdated files in UserFileTable\n");
				return;
			}
			else if (!rmOutdatedFiles(path + "/InboxTable"))
			{
				fprintf(stderr, "Error: Fail to remove outdated files in InboxTable\n");
				return;
			}

			try
			{
				fs::path oldLogFilePath = path + "/log" + std::to_string(cpVersion) + ".txt";
				fs::remove(oldLogFilePath);
			}
			catch (fs::filesystem_error &e)
			{
				fprintf(stderr, "Error: Fail to remove outdated log file\n");
				return;
			}

			if (verbose)
			{
				printf("Secondary: Outdated files removed\n");
			}

			// asking primary for actual data
			backendMessage dataFileReqMsg = backendMessage(
				backendMessage::DataFileReq, "", 1);
			dataFileReqMsg.setDataFileReqMsg(ownIp + ":" + std::to_string(ownPort));
			forwardToPeers(dataFileReqMsg, primaryIpPort);
			return;
		}

		// if the logfile version matches, ask primary for the new entries in the log file
		backendMessage logEntryReqMsg = backendMessage(backendMessage::LogEntryReq, request.msgId, 1);
		logEntryReqMsg.setLogEntryReqMsg(ownIp + ":" + std::to_string(ownPort), std::to_string(offset));
		forwardToPeers(logEntryReqMsg, primaryIpPort);
	}
	else if (request.msgType == backendMessage::DataFileReq)
	{
		if (groupRole == "primary")
		{
			if (verbose)
			{
				printf("Primary: Data file request received from worker\n");
			}
			// send a data files response
			if (!sendTableFiles("UserInfoTable", commFd))
			{
				fprintf(stderr, "Error: Fail to send data files for UserInfoTable\n");
			}
			if (!sendTableFiles("UserFileTable", commFd))
			{
				fprintf(stderr, "Error: Fail to send data files for UserFileTable\n");
			}
			if (!sendTableFiles("InboxTable", commFd))
			{
				fprintf(stderr, "Error: Fail to send data files for InboxTable\n");
			}

			if (verbose)
			{
				// printf("Primary: Data files sent\n");
			}

			// send the log file
			int logFd = open(logFilePath.c_str(), O_RDONLY);
			if (logFd < 0)
			{
				printf("DataFileReq: Cannot open log file %s: %s\n",
					   logFilePath.c_str(), strerror(errno));
				return;
			}
			char logBuffer[CONTENTLENGTH];
			backendMessage logFileRspMsg = backendMessage(backendMessage::DataFileRsp, "", 1);
			while (true)
			{
				int readBytes = read(logFd, logBuffer, CONTENTLENGTH);
				if (readBytes < 0)
				{
					printf("Error: Cannot read log file %s: %s\n",
						   logFilePath.c_str(), strerror(errno));
					return;
				}
				std::string content(logBuffer, readBytes);
				logFileRspMsg.setDataFileRspMsg(logFilePath.substr(logFilePath.find_last_of("/") + 1), content);

				std::vector<char> buffer;
				logFileRspMsg.serialize(buffer);
				write(commFd, buffer.data(), buffer.size());
				if (readBytes == 0)
				{
					break;
				}
			}
			close(logFd);
			if (verbose)
			{
				// printf("Primary: Log file sent\n");
			}
			backendMessage allDataDoneMsg = backendMessage(backendMessage::DataFileRsp, "", 1);
			allDataDoneMsg.setDataFileRspMsg("allDataDone", "");
			std::vector<char> buffer;
			allDataDoneMsg.serialize(buffer);
			write(commFd, buffer.data(), buffer.size());
			if (verbose)
			{
				printf("Primary: All data files sent\n");
			}
		}
		else
		{
			fprintf(stderr,
					"Error: Data file request sent to non-primary worker\n");
		}
	}
	else if (request.msgType == backendMessage::DataFileRsp)
	{
		backendMessage::DataFileRspMsg dataFileRspMsg = request.getDataFileRspMsg();
		std::string dirName = path + "/" + dataFileRspMsg.dirName;
		std::string fileName = dataFileRspMsg.dirName;

		// check if all data files are received
		if (fileName == "allDataDone")
		{
			off_t offset = rebuildInMemTable(logFilePath, 0);
			if (verbose)
			{
				printf("All data files received, rebuild in-memory table done\n");
			}
			// ask for the new entries in the log file
			backendMessage logEntryReqMsg = backendMessage(backendMessage::LogEntryReq, "", 1);
			logEntryReqMsg.setLogEntryReqMsg(ownIp + ":" + std::to_string(ownPort), std::to_string(offset));
			forwardToPeers(logEntryReqMsg, primaryIpPort);
			return;
		}

		// update the cpVersion for new log file
		if (fileName.find("log") != std::string::npos)
		{
			cpVersion = std::stoul((fileName.substr(0, fileName.find_first_of("."))).substr(3));
			logFilePath = dirName;
		}

		// write the data to the file
		std::string data = dataFileRspMsg.data;
		if (verbose)
		{
			// printf("Data file response received for %s\n", dirName.c_str());
		}

		int fileFd = open(dirName.c_str(), O_CREAT | O_RDWR | O_APPEND, 0777);
		if (fileFd < 0)
		{
			printf("Error: Cannot open data file %s: %s\n",
				   dirName.c_str(), strerror(errno));
			return;
		}
		int writeBytes = write(fileFd, data.c_str(), data.size());
		if (writeBytes < 0 || writeBytes != data.size())
		{
			printf("Error: Cannot write data file %s: %s\n",
				   dirName.c_str(), strerror(errno));
			return;
		}
		close(fileFd);
		listOnDiskFiles();
	}
	else if (request.msgType == backendMessage::LogEntryReq)
	{
		if (verbose)
		{
			printf("Primary: Log entry request received\n");
		}
		if (groupRole == "primary")
		{
			backendMessage::LogEntryReqMsg logEntryReqMsg = request.getLogEntryReqMsg();
			std::string sourceId = logEntryReqMsg.workerId;
			off_t offset = std::stoul(logEntryReqMsg.offset);
			int logFd = open(logFilePath.c_str(), O_RDONLY);
			if (logFd < 0)
			{
				printf("Error: Cannot open log file %s: %s\n",
					   logFilePath.c_str(), strerror(errno));
				return;
			}

			backendMessage logEntryRspMsg = backendMessage(backendMessage::LogEntryRsp, "", 1);
			std::vector<char> buffer;
			off_t logFileSize = lseek(logFd, 0, SEEK_END);
			if (logFileSize <= offset) {
				logEntryRspMsg.setLogEntryRspMsg(std::to_string(logFileSize), "");
				logEntryRspMsg.serialize(buffer);
				write(commFd, buffer.data(), buffer.size());
				close(logFd);
				return;
			}
			lseek(logFd, offset, SEEK_SET);
			char logBuffer[CONTENTLENGTH];
			while (true)
			{
				int readBytes = read(logFd, logBuffer, CONTENTLENGTH);
				if (readBytes < 0)
				{
					printf("LogEntryReq: Cannot read log file %s: %s\n",
						   logFilePath.c_str(), strerror(errno));
					return;
				}
				std::string content(logBuffer, readBytes);
				logEntryRspMsg.setLogEntryRspMsg(std::to_string(logFileSize), content);
				logEntryRspMsg.serialize(buffer);
				write(commFd, buffer.data(), buffer.size());
				if (readBytes + offset == logFileSize) // end of file
				{
					break;
				}
			}
			close(logFd);
			if (verbose)
			{
				printf("Primary: Log entries sent\n");
			}
		}
		else
		{
			fprintf(stderr,
					"Error: Log entry request sent to non-primary worker\n");
		}
	}
	else if (request.msgType == backendMessage::LogEntryRsp)
	{
		if (verbose)
		{
			printf("Log entry response received\n");
		}
		off_t offset = std::stoul(request.getLogEntryRspMsg().logFileSize);
		int logFd = open(logFilePath.c_str(), O_WRONLY | O_APPEND);
		if (logFd < 0)
		{
			printf("LogEntryRsp: Cannot open log file %s: %s\n",
				   logFilePath.c_str(), strerror(errno));
			return;
		}
		off_t currOffset = lseek(logFd, 0, SEEK_END);
		off_t prevOffset = currOffset;
		std::string logBuffer = request.getLogEntryRspMsg().logFileData;
		int writeBytes = write(logFd, logBuffer.c_str(), logBuffer.size());
		if (writeBytes < 0)
		{
			printf("Error: Cannot write log file %s: %s\n",
				   logFilePath.c_str(), strerror(errno));
			return;
		}
		currOffset += writeBytes;
		close(logFd);

		// sanity check for the log file size
		if (currOffset != offset)
		{
			fprintf(stderr, "Error: Rebuild log file size mismatch\n");
		}
		if (verbose)
		{
			printf("Log entries up-to-date\n");
		}

		// rebuild the in-memory table for new log entries
		off_t newOffset = rebuildInMemTable(logFilePath, prevOffset);
		if (verbose)
		{
			printf("Rebuild in-memory table for new log entries done\n");
			// printf("New offset: %ld\n", newOffset);
		}

		// send recoveryDone message to coordinator
		std::vector<char> buffer;
		backendMessage recoveryDoneMsg = backendMessage(backendMessage::RecoveryDone, "", 1);
		recoveryDoneMsg.setRecoveryDoneMsg(ownIp + ":" + std::to_string(ownPort));
		recoveryDoneMsg.serialize(buffer);
		write(coordSocket, buffer.data(), buffer.size());
		if (verbose)
		{
			printf("Secondary worker %s recovery done\n", (ownIp + ":" + std::to_string(ownPort)).c_str());
		}
	}
	else if (request.msgType == backendMessage::Ping)
	{
		peerFdMap[request.msgId] = commFd;
		if (verbose)
		{
			printf("Peer connection established with %s\n", request.msgId.c_str());
			std::cout << "Secondary FD: " << commFd << std::endl;
		}
	}
	else
	{
		// invalid message types
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::ERR,
						 "No matching message type");
		rspMsg.serialize(rspBuffer);
		write(fds[index], rspBuffer.data(), rspBuffer.size());
	}
}

/*
 * A function that creates a connection with peers
 * Input: peerIpPort, the ip:port of the peer
 * Output: true if the connection is successfully created, false otherwise
 */

bool createPeerConnections(std::string peerIpPort)
{
	int peerSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (peerSocket < 0)
	{
		printf("Cannot open peer socket because: %s\n", strerror(errno));
		return false;
	}
	struct sockaddr_in peerAddr;
	bzero(&peerAddr, sizeof(peerAddr));
	peerAddr.sin_family = AF_INET;
	peerAddr.sin_addr.s_addr = inet_addr(
		peerIpPort.substr(0, peerIpPort.find(":")).c_str());
	peerAddr.sin_port = htons(
		std::stoi(
			peerIpPort.substr(peerIpPort.find(":") + 1,
							  peerIpPort.length())));
	if (connect(peerSocket, (struct sockaddr *)&peerAddr, sizeof(peerAddr)) < 0)
	{
		printf("Cannot connect to peer because: %s\n", strerror(errno));
		return false;
	}
	peerFdMap[peerIpPort] = peerSocket;

	// create a worker thread for the peer connection
	// check if there are free spots
	pthread_mutex_lock(&lock);
	if (fdCount >= NUMTHREADS)
	{
		pthread_mutex_unlock(&lock);
		if (verbose)
			std::cerr << "Cannot create connection because no free spots\n";
		return false;
	}

	// find a spot
	int index = 0;
	while (fds[index] != 0)
		index++;
	if (verbose)
		std::cerr << "found index: " << index << "\n";
	pthread_mutex_unlock(&lock);

	if (verbose)
		std::cerr << "Ready to create fd\n";
	pthread_mutex_unlock(&lock);
	fds[index] = peerSocket;
	fdCount++;
	pthread_mutex_unlock(&lock);

	args[index]->index = index;
	args[index]->fd = peerSocket;
	pthread_create(&threads[index], NULL, worker, args[index]);

	if (verbose)
	{
		std::cout << "Peer connection established with " << peerIpPort << "\n";
		std::cout << "Peer socket: " << peerSocket << "\n";
	}
	return true;
}

/*
 * A function that parses an assignment from the coordinator
 * Input: assignment, the assignment message
 */
void parseAssignment(backendMessage::AssignMsg assignment)
{
	// do recovery if first come to alive
	bool needRecovery = groupRole == "unassigned" ? true : false;
	groupRole = assignment.role;
	primaryIpPort = assignment.primaryIpPort;
	secondaryIpPorts = assignment.secondaryIpPort;
	std::pair<char, char> numKeyRange = assignment.numKeyRange;
	std::pair<char, char> letterKeyRange = assignment.letterKeyRange;
	secondariesReady = assignment.numSecondariesReady;
	if (verbose)
	{
		printf("Get assigned role: %s\n", groupRole.c_str());
		printf("Number of workers in the group: %ld\n",
			   secondaryIpPorts.size() + 1);
	}

	// record key range locally if first get assigned
	std::string keyRangePath = path + "/keyRange.txt";
	fs::path keyRangeFile(keyRangePath);
	if (!fs::exists(keyRangeFile))
	{
		int fd = open(keyRangePath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0744);
		if (fd < 0)
		{
			printf("Cannot open file %s: %s\n", keyRangePath.c_str(),
				   strerror(errno));
		}
		write(fd, &letterKeyRange.first, 1);
		write(fd, &letterKeyRange.second, 1);
		write(fd, &numKeyRange.first, 1);
		write(fd, &numKeyRange.second, 1);
		close(fd);
	}

	if (groupRole == "secondary")
	{
		if (verbose)
		{
			printf("Secondary worker %s creating a connection with primary\n", ownIp.c_str());
		}
		// ping the primary workers in the same group to create TCP connections among workers
		backendMessage pingMsg = backendMessage(backendMessage::Ping, ownIp + ":" + std::to_string(ownPort), 1);
		pingMsg.setPingMsg('F', std::make_pair('0', '0'), std::make_pair('0', '0'));
		if (!createPeerConnections(primaryIpPort))
		{
			printf("Fail to create peer connection with %s\n",
				   primaryIpPort.c_str());
		}
		forwardToPeers(pingMsg, primaryIpPort);
	}
	else if (groupRole == "primary")
	{
		if (verbose)
		{
			printf("Primary worker %s checking if there is finished work\n", ownIp.c_str());
		}
		// check if CP is done after knowing some worker died
		pthread_mutex_lock(&cpMutex);
		if (numCPFinished == secondaryIpPorts.size() + 1)
		{
			pthread_mutex_unlock(&cpMutex);
			// all workers have finished checkpointing, send ack to everyone to resume working
			std::vector<char> buffer;
			backendMessage cpAckMsg = backendMessage(backendMessage::CPAck, "",
													 1);
			cpAckMsg.setCPAckMsg(backendMessage::responseType::OK);
			cpAckMsg.serialize(buffer);
			for (auto it = secondaryIpPorts.begin();
				 it != secondaryIpPorts.end(); it++)
			{
				forwardToPeers(cpAckMsg, *it);
				printf("send cpAck to %s\n", it->c_str());
			}
			clearQueue();
			numCPFinished = 0;
			lastCPSuccess = false;
		}
		else
		{
			pthread_mutex_unlock(&cpMutex);
		}
		if (lastCPSuccess == true)
		{ // secondary finished CP
			// if no secondary, return to normal
			if (secondaryIpPorts.size() == 0)
			{
				clearQueue();
				numCPFinished = 0;
				lastCPSuccess = false;
			}
			else
			{
				// send the same CP REQ to other secondaries
				numCPFinished = 1;
				std::vector<char> buffer;
				backendMessage cpMsg = backendMessage(backendMessage::CP, "", 1);
				cpMsg.setCPMsg(cpVersion);
				cpMsg.serialize(buffer);
				for (auto it = secondaryIpPorts.begin();
					 it != secondaryIpPorts.end(); it++)
				{
					forwardToPeers(cpMsg, *it);
				}
			}
		}
		// check if any message can be sent out after knowing some worker died
		std::vector<int> finishedMsgIndex;
		for (auto it = ackCounter.begin(); it != ackCounter.end(); ++it)
		{
			int index = msgId2Index[it->first];
			pthread_mutex_lock(&counterLocks[msgIds[index]]);
			if (ackCounter[msgIds[index]] == secondariesReady + 1)
			{
				deliverRsp(index);
				printf("deliver rsp\n");
			}
			pthread_mutex_unlock(&counterLocks[msgIds[index]]);
		}
		for (auto it = finishedMsgIndex.begin(); it != finishedMsgIndex.end(); ++it)
		{
			deliverRsp(*it);
		}
	}
	else
	{
		fprintf(stderr, "Error: Unknown assigned role %s\n", groupRole.c_str());
	}

	// check if need recovery
	if (needRecovery)
	{
		doRecovery();
	}
}

/*
 * A function that creates a connection and forwards a message to the peers
 * Input: msg, the message to forward
 * 		  ipPort, the ip:port of the peer
 */
void forwardToPeers(backendMessage msg, std::string ipPort)
{
	if (isCheckpointing && msg.msgType != backendMessage::CPAck)
	{
		if (verbose)
		{
			printf("Checkpointing, message not forwarded\n");
		}
		pthread_mutex_lock(&outQueueLock);
		outQueue.push_back(std::tuple<backendMessage, std::string>(msg, ipPort));
		pthread_mutex_unlock(&outQueueLock);
		return;
	}
	int peerSocket = peerFdMap[ipPort];
	std::vector<char> buffer;
	msg.serialize(buffer);
	int writeBytes = write(peerSocket, buffer.data(), buffer.size());
	if (writeBytes < 0)
	{
		printf("Error: Cannot write to peer %s: %s\n", ipPort.c_str(),
			   strerror(errno));
	}
	if (verbose)
	{
		printf("Message forwarded to %s, fd: %d\n", ipPort.c_str(), peerSocket);
	}
}

/*
 * A function that updates the log file during checkpointing
 */

void updateLogFile()
{
	if (verbose)
	{
		printf("Cleaning up on disk files and in memory resources\n");
	}
	std::string newLogFile = path + "/log" + std::to_string(cpVersion) + ".txt";
	std::string oldLogFile = logFilePath;
	if (newLogFile == logFilePath)
	{
		oldLogFile = path + "/log" + std::to_string(cpVersion - 1) + ".txt";
	}
	if (verbose)
	{
		printf("New log file path: %s\n", newLogFile.c_str());
		printf("Old log file path: %s\n", oldLogFile.c_str());
	}
	int newLogFd = open(newLogFile.c_str(), O_CREAT | O_RDWR | O_APPEND,
						0777);
	char *opBuffer = (char *)malloc(BUFFERLENGTH);
	if (fs::exists(oldLogFile))
	{
		int oldLogFd = open(oldLogFile.c_str(), O_RDONLY);
		// copy unfinished operations to the new log file
		for (auto it = userTable.begin(); it != userTable.end(); ++it)
		{
			std::string rowName = it->first;
			for (auto it2 = userTable.at(rowName).begin();
				 it2 != userTable.at(rowName).end(); ++it2)
			{
				if (std::get<1>(it2->second) == 1)
				{
					continue;
				}
				std::string colName = it2->first;
				off_t opOffset = std::get<2>(it2->second);
				lseek(oldLogFd, opOffset, SEEK_SET);
				memset(opBuffer, 0, BUFFERLENGTH);
				int readBytes = read(oldLogFd, opBuffer, BUFFERLENGTH);
				if (readBytes < 0)
				{
					printf("Error: Cannot read operation message\n");
					continue;
				}
				backendMessage opMsg = backendMessage();
				if (!opMsg.deserialize(opBuffer, readBytes))
				{
					printf("UpdateLogFile: Cannot deserialize operation message\n");
					continue;
				}
				std::vector<char> buf;
				opMsg.serialize(buf);
				off_t newOffset = lseek(newLogFd, 0, SEEK_END);
				write(newLogFd, buf.data(), buf.size());
				std::string operation = std::get<0>(it2->second);
				int isEnd = std::get<1>(it2->second);
				std::string val = std::get<3>(it2->second);
				userTable.at(rowName)[colName] = std::make_tuple(operation, isEnd,
																 newOffset, val);
			}
		}
		for (auto it = fileTable.begin(); it != fileTable.end(); ++it)
		{
			std::string rowName = it->first;
			for (auto it2 = fileTable.at(rowName).begin();
				 it2 != fileTable.at(rowName).end(); ++it2)
			{
				if (std::get<1>(it2->second) == 1)
				{
					continue;
				}
				std::string colName = it2->first;
				off_t opOffset = std::get<2>(it2->second);
				lseek(oldLogFd, opOffset, SEEK_SET);
				memset(opBuffer, 0, BUFFERLENGTH);
				int readBytes = read(oldLogFd, opBuffer, BUFFERLENGTH);
				if (readBytes < 0)
				{
					printf("Error: Cannot read operation message\n");
					continue;
				}
				backendMessage opMsg = backendMessage();
				if (!opMsg.deserialize(opBuffer, readBytes))
				{
					printf("UpdateLogFile: Cannot deserialize operation message\n");
					continue;
				}
				std::vector<char> buf;
				opMsg.serialize(buf);
				off_t newOffset = lseek(newLogFd, 0, SEEK_END);
				write(newLogFd, buf.data(), buf.size());
				std::string operation = std::get<0>(it2->second);
				int isEnd = std::get<1>(it2->second);
				std::string val = std::get<3>(it2->second);
				userTable.at(rowName)[colName] = std::make_tuple(operation, isEnd,
																 newOffset, val);
			}
		}
		for (auto it = inboxTable.begin(); it != inboxTable.end(); ++it)
		{
			std::string rowName = it->first;
			for (auto it2 = inboxTable.at(rowName).begin();
				 it2 != inboxTable.at(rowName).end(); ++it2)
			{
				if (std::get<1>(it2->second) == 1)
				{
					continue;
				}
				std::string colName = it2->first;
				off_t opOffset = std::get<2>(it2->second);
				lseek(oldLogFd, opOffset, SEEK_SET);
				memset(opBuffer, 0, BUFFERLENGTH);
				int readBytes = read(oldLogFd, opBuffer, BUFFERLENGTH);
				if (readBytes < 0)
				{
					printf("Error: Cannot read operation message\n");
					continue;
				}
				backendMessage opMsg = backendMessage();
				if (!opMsg.deserialize(opBuffer, readBytes))
				{
					printf("UpdateLogFile: Cannot deserialize operation message\n");
					continue;
				}
				std::vector<char> buf;
				opMsg.serialize(buf);
				off_t newOffset = lseek(newLogFd, 0, SEEK_END);
				write(newLogFd, buf.data(), buf.size());
				std::string operation = std::get<0>(it2->second);
				int isEnd = std::get<1>(it2->second);
				std::string val = std::get<3>(it2->second);
				userTable.at(rowName)[colName] = std::make_tuple(operation, isEnd,
																 newOffset, val);
			}
		}
		for (auto it = inboxTable.begin(); it != inboxTable.end(); ++it)
		{
			std::string rowName = it->first;
			for (auto it2 = inboxTable.at(rowName).begin();
				 it2 != inboxTable.at(rowName).end(); ++it2)
			{
				if (std::get<1>(it2->second) == 1)
				{
					continue;
				}
				std::string colName = it2->first;
				off_t opOffset = std::get<2>(it2->second);
				lseek(oldLogFd, opOffset, SEEK_SET);
				memset(opBuffer, 0, BUFFERLENGTH);
				int readBytes = read(oldLogFd, opBuffer, BUFFERLENGTH);
				if (readBytes < 0)
				{
					printf("Error: Cannot read operation message\n");
					continue;
				}
				backendMessage opMsg = backendMessage();
				if (!opMsg.deserialize(opBuffer, readBytes))
				{
					printf("UpdateLogFile: Cannot deserialize operation message\n");
					continue;
				}
				std::vector<char> buf;
				opMsg.serialize(buf);
				off_t newOffset = lseek(newLogFd, 0, SEEK_END);
				write(newLogFd, buf.data(), buf.size());
				std::string operation = std::get<0>(it2->second);
				int isEnd = std::get<1>(it2->second);
				std::string val = std::get<3>(it2->second);
				userTable.at(rowName)[colName] = std::make_tuple(operation, isEnd,
																 newOffset, val);
			}
		}
		close(oldLogFd);
	}
	else
	{
		printf("Old log file does not exist\n");
	}

	printf("Starting to write to tmp file\n");

	// write the log for queued requests to new log file
	std::string tmpLogFile = path + "/logTmp.txt";
	fs::path tmpFileToDelete(tmpLogFile);
	bool existsTmpLog = fs::exists(tmpFileToDelete);
	if (existsTmpLog)
	{
		pthread_mutex_lock(&logFileMutex);
		int tmpLogFd = open(tmpLogFile.c_str(), O_RDONLY);
		if (tmpLogFd < 0)
		{
			close(newLogFd);
			pthread_mutex_unlock(&logFileMutex);
			printf("updateLogRequest: Cannot open file %s: %s\n",
				   tmpLogFile.c_str(), strerror(errno));
		}
		while (true)
		{
			memset(opBuffer, 0, BUFFERLENGTH);
			int readBytes = read(tmpLogFd, opBuffer, BUFFERLENGTH);
			if (readBytes == 0)
			{
				break;
			}
			if (readBytes < 0)
			{
				printf("Error: %s\n", strerror(errno));
				break;
			}
			int writeBytes = write(newLogFd, opBuffer, readBytes);
			if (writeBytes < 0 || writeBytes != readBytes)
			{
				printf("Error: %s\n", strerror(errno));
				break;
			}
		}
		close(tmpLogFd);
		close(newLogFd);

		try
		{
			fs::remove(tmpFileToDelete);
		}
		catch (fs::filesystem_error &e)
		{
			printf("Error: %s\n", e.what());
		}
		pthread_mutex_unlock(&logFileMutex);
	}

	fs::path oldFileToDelete(logFilePath);
	try
	{
		fs::remove(oldFileToDelete);
	}
	catch (fs::filesystem_error &e)
	{
		printf("Error: %s\n", e.what());
	}

	logFilePath = newLogFile;
	free(opBuffer);
	opBuffer = NULL;
	printf("New log file path: %s\n", logFilePath.c_str());
}

/*
 * A function that performs a checkpoint
 */
bool doCheckpoint()
{
	if (isCheckpointing)
	{
		return false;
	}
	if (verbose)
	{
		printf("Starting checkpointing for version #%d\n", cpVersion);
	}
	isCheckpointing = true;
	bool cpSuccess = true;

	if (!writeToDisk(&userTable, &userOffsets, &userRawCols,
					 &userTableLocks, "UserInfoTable"))
	{
		cpSuccess = false;
	}
	if (!writeToDisk(&fileTable, &fileOffsets, &fileRawCols,
					 &fileTableLocks, "UserFileTable"))
	{
		cpSuccess = false;
	}
	if (!writeToDisk(&inboxTable, &inboxOffsets, &inboxRawCols,
					 &inboxTableLocks, "InboxTable"))
	{
		cpSuccess = false;
	}

	if (cpSuccess)
	{
		updateLogFile();
		if (verbose)
		{
			printf("Checkpointing success for version #%d\n", cpVersion);
		}
	}
	else
	{
		printf("Checkpointing failed for version #%d\n", cpVersion);
	}
	return cpSuccess;
	// TODO: handle the case that log fails
}

/*
 * A function that allows the server to restore its state so it is consistent with the group
 */
void doRecovery()
{
	// backendMessage msg = backendMessage(backendMessage::RecoveryDone, "", 1);
	// msg.setRecoveryDoneMsg(ownIp + ":" + std::to_string(ownPort));
	// std::vector<char> buffer;
	// msg.serialize(buffer);
	// write(coordSocket, buffer.data(), buffer.size());
	// return;

	if (verbose)
	{
		printf("Worker %s:%d is recovering\n", ownIp.c_str(), ownPort);
	}

	// get the local log file if there is one
	std::vector<std::string> logFiles = findLogFiles();
	std::string tmpLogFilePath = logFiles[1];
	std::string newLogFilePath = logFiles[2];
	std::string oldLogFilePath = logFiles[0];
	listOnDiskFiles();

	// ask primary for the latest log file if it is not the primary
	if (groupRole == "primary")
	{
		if (verbose)
		{
			printf("Primary worker %s:%d recovering locally\n", ownIp.c_str(), ownPort);
		}
		recoverFromLocalLog(oldLogFilePath, tmpLogFilePath, newLogFilePath);
		// send recovery done message to the coordinator
		std::vector<char> buffer;
		backendMessage msg = backendMessage(backendMessage::RecoveryDone, "1", 1);
		msg.setRecoveryDoneMsg(ownIp + ":" + std::to_string(ownPort));
		msg.serialize(buffer);
		int writeBytes = write(coordSocket, buffer.data(), buffer.size());
		if (writeBytes < 0)
		{
			fprintf(stderr, "Fail write to socket (%s)\n", strerror(errno));
		}
		if (verbose)
		{
			printf("Primary worker %s:%d recovery done\n", ownIp.c_str(), ownPort);
		}
	}
	else if (groupRole == "secondary")
	{
		if (verbose)
		{
			printf("Secondary worker %s:%d requesting log file from primary\n", ownIp.c_str(), ownPort);
		}
		backendMessage logFileReqMsg = backendMessage(backendMessage::LogFileReq,
													  "", 1);
		logFileReqMsg.setLogFileReqMsg(ownIp + ":" + std::to_string(ownPort));
		forwardToPeers(logFileReqMsg, primaryIpPort);
	}
	else
	{
		fprintf(stderr, "Error: Worker role %s not assigned\n", groupRole.c_str());
	}
}

/*
 * A function that restores the in-memory table from the local log file
 * Handles 3 cases: only one log file,
 * 					previous version log file + tmp log file,
 * 					old log file + tmp log file + new log file
 * Input: oldLogFilePath, the old log file path
 * 		  tmpLogFilePath, the tmp log file path
 * 		  newLogFilePath, the new log file path
 * Return: the offset of the last operation in the log file
 * 		  0 if the log file is empty
 */
off_t recoverFromLocalLog(std::string oldLogFilePath, std::string tmpLogFilePath, std::string newLogFilePath)
{
	off_t offset = 0;
	if (tmpLogFilePath == "" && oldLogFilePath == "")
	{ // only one log file
		if (verbose)
		{
			printf("Only one log file found, recovering from log file %s\n", newLogFilePath.c_str());
		}
		offset = rebuildInMemTable(newLogFilePath, 0);
	}
	else if (tmpLogFilePath != "" && oldLogFilePath != "" && newLogFilePath != "")
	{ // old log file + tmp log file + new log file
		// the worker died while update the log file, delete old log file and update the log file
		// then rebuild in-memory table
		if (verbose)
		{
			printf("Old log file, tmp log file and new log file found\n");
		}
		fs::path logFileToDelete(newLogFilePath);
		try
		{
			fs::remove(logFileToDelete);
		}
		catch (fs::filesystem_error &e)
		{
			printf("Error: %s\n", e.what());
		}
		logFilePath = path + "/log" + std::to_string(cpVersion - 1) + ".txt";
		updateLogFile();
		offset = rebuildInMemTable(logFilePath, 0);
	}
	else if (oldLogFilePath == "" && tmpLogFilePath != "" && newLogFilePath != "")
	{ // previous version log file + tmp log file
		// the worker died while checkpointing, so rebuild previous in memory table
		// redo checkpoint
		// then rebuild in-memory table
		if (verbose)
		{
			printf("Previous version log file and tmp log file found, redo checkpointing and recover from log file\n");
		}
		rebuildInMemTable(newLogFilePath, 0);
		doCheckpoint();
		isCheckpointing = false;
		offset = rebuildInMemTable(logFilePath, 0);
	}
	else
	{
		fprintf(stderr, "Error: Unexpected input for recoverFromLocalLog\n");
		fprintf(stderr, "oldLogFilePath: %s\n", oldLogFilePath.c_str());
		fprintf(stderr, "tmpLogFilePath: %s\n", tmpLogFilePath.c_str());
		fprintf(stderr, "newLogFilePath: %s\n", newLogFilePath.c_str());
	}
	return offset;
}

/*
 * A function to restore the in memory tables using on disk log file starting from an offset
 * Input: filePath, the path to the log file
 * 		  startOffset, the offset to start reading the log file
 * Return: the offset of the last operation in the log file
 * 		  0 if the log file is empty
 */
off_t rebuildInMemTable(std::string filePath, off_t startOffset)
{
	if (verbose)
	{
		printf("Rebuilding in memory table from log file %s\n", filePath.c_str());
	}
	int logFd = open(logFilePath.c_str(), O_RDONLY);
	if (logFd < 0)
	{
		printf("recoverFromLocalLog: Cannot open log file %s: %s\n",
			   logFilePath.c_str(), strerror(errno));
		return -1;
	}
	// check if the log file is empty
	off_t fileSize = lseek(logFd, 0, SEEK_END);
	if (verbose)
	{
		printf("rebuildInMemTable: Log file size: %ld\n", fileSize);
		printf("rebuildInMemTable: Start offset: %ld\n", startOffset);
	}
	if (fileSize == 0)
	{
		close(logFd);
		return 0;
	}
	else if (startOffset >= fileSize)
	{
		close(logFd);
		return fileSize;
	}

	int readBytes = 0;
	off_t offset = startOffset;
	off_t msgOffset = startOffset;
	int msgSize = 0;
	bool canRedo = true;
	char *msgBuffer = (char *)malloc(BUFFERLENGTH);
	bool keepRun = true;
	while (true)
	{
		if (!keepRun)
		{
			break;
		}
		if (offset < fileSize)
		{
			if (lseek(logFd, offset, SEEK_SET) < 0)
			{
				printf("Error: Cannot seek to offset %ld in log file %s: %s\n",
					   offset, logFilePath.c_str(), strerror(errno));
				return -1;
			}
			int n = read(logFd, msgBuffer + readBytes, BUFFERLENGTH - readBytes);
			if (n < 0)
			{
				printf("Error in reading log file: %s\n", strerror(errno));
				break;
			}
			offset += n;
			readBytes += n;
		}

		std::map<std::string, std::map<std::string, std::tuple<std::string, int, off_t, std::string>>> *currTable;
		std::map<std::string, std::map<std::string, pthread_mutex_t>> *currTableLocks;
		std::map<std::string, std::map<std::string, uint64_t>> *currOffsets;
		pthread_mutex_t *currOffsetLock;
		std::map<std::string, std::set<std::tuple<std::string, int>>> *currRawCols;
		std::map<std::string, pthread_mutex_t> *currRawColsLocks;

		backendMessage msg = backendMessage();
		if (!msg.deserialize(msgBuffer, readBytes))
		{
			printf("RebuildInMemTable: Cannot deserialize message\n");
			keepRun = false;
			break;
		}

		if (msg.msgType == backendMessage::Req || msg.msgType == backendMessage::Notify)
		{
			if (msg.msgType == backendMessage::Notify)
			{
				backendMessage::NotifyMsg notifyMsg = msg.getNotifyMsg();
				msg.setReqMsg(notifyMsg.reqType, notifyMsg.tableName, notifyMsg.rowName,
							  notifyMsg.colName, "", notifyMsg.newVal);
			}
			backendMessage::ReqMsg reqMsg = msg.getReqMsg();
			std::string table = reqMsg.tableName;
			if (table == "UserInfoTable")
			{
				currTable = &userTable;
				currTableLocks = &userTableLocks;
				currOffsets = &userOffsets;
				currOffsetLock = &userOffsetLock;
				currRawCols = &userRawCols;
				currRawColsLocks = &userRawColsLocks;
			}
			else if (table == "UserFileTable")
			{
				currTable = &fileTable;
				currTableLocks = &fileTableLocks;
				currOffsets = &fileOffsets;
				currOffsetLock = &fileOffsetLock;
				currRawCols = &fileRawCols;
				currRawColsLocks = &fileRawColsLocks;
			}
			else if (table == "InboxTable")
			{
				currTable = &inboxTable;
				currTableLocks = &inboxTableLocks;
				currOffsets = &inboxOffsets;
				currOffsetLock = &inboxOffsetLock;
				currRawCols = &inboxRawCols;
				currRawColsLocks = &inboxRawColsLocks;
			}
			else
			{
				fprintf(stderr, "Redo request failed: No matching table for %s\n", table.c_str());
				canRedo = false;
			}

			if (canRedo)
			{
				if (reqMsg.reqType == backendMessage::requestType::PUT)
				{
					putToTable(currTable, currTableLocks, currRawCols, currRawColsLocks,
							   computeDigest(reqMsg.rowName), computeDigest(reqMsg.colName), reqMsg.colName,
							   reqMsg.newVal, msg.isEnd, true, msgOffset);
				}
				else if (reqMsg.reqType == backendMessage::requestType::CPUT)
				{
					bool foundMatch = false;
					foundMatch = checkCputCond(currTable, reqMsg.tableName,
											   currOffsetLock, currTableLocks, currOffsets, computeDigest(reqMsg.rowName),
											   computeDigest(reqMsg.colName), reqMsg.matchVal,
											   false, -1, -1);
					if (foundMatch)
					{
						putToTable(currTable, currTableLocks, currRawCols, currRawColsLocks,
								   computeDigest(reqMsg.rowName), computeDigest(reqMsg.colName), reqMsg.colName,
								   reqMsg.newVal, msg.isEnd, true, msgOffset);
					}
				}
				else if (reqMsg.reqType == backendMessage::requestType::DELETE)
				{
					if (checkDeleteCond(currTable, currOffsets, currOffsetLock, currTableLocks,
										table, computeDigest(reqMsg.rowName), computeDigest(reqMsg.colName)) == "OK")
					{
						deleteOperation(currTable, currOffsets, currOffsetLock, currTableLocks,
										currRawCols, currRawColsLocks, table, computeDigest(reqMsg.rowName),
										computeDigest(reqMsg.colName), reqMsg.colName, msgOffset);
					}
				}
				else if (reqMsg.reqType == backendMessage::requestType::APPEND)
				{
					appendOperation(currTable, currTableLocks, currRawCols, currRawColsLocks,
									computeDigest(reqMsg.rowName), computeDigest(reqMsg.colName), reqMsg.colName,
									reqMsg.newVal, msg.isEnd, msgOffset);
				}
				else
				{
					// no matching request type
					fprintf(stderr,
							"Error: Redo request failed, no matching request type for %d\n", reqMsg.reqType);
				}
			}
		}
		else if (msg.msgType == backendMessage::Append)
		{
			backendMessage::AppendMsg appendMsg = msg.getAppendMsg();
			if (appendMsg.tableName == "UserInfoTable")
			{
				currTable = &userTable;
				currTableLocks = &userTableLocks;
				currOffsets = &userOffsets;
				currOffsetLock = &userOffsetLock;
				currRawCols = &userRawCols;
				currRawColsLocks = &userRawColsLocks;
			}
			else if (appendMsg.tableName == "UserFileTable")
			{
				currTable = &fileTable;
				currTableLocks = &fileTableLocks;
				currOffsets = &fileOffsets;
				currOffsetLock = &fileOffsetLock;
				currRawCols = &fileRawCols;
				currRawColsLocks = &fileRawColsLocks;
			}
			else if (appendMsg.tableName == "InboxTable")
			{
				currTable = &inboxTable;
				currTableLocks = &inboxTableLocks;
				currOffsets = &inboxOffsets;
				currOffsetLock = &inboxOffsetLock;
				currRawCols = &inboxRawCols;
				currRawColsLocks = &inboxRawColsLocks;
			}
			appendOperation(currTable, currTableLocks, currRawCols, currRawColsLocks,
							computeDigest(appendMsg.rowName), computeDigest(appendMsg.colName),
							appendMsg.colName, appendMsg.appendMsg, msg.isEnd, msgOffset);
		}
		else
		{
			// no matching message type
			fprintf(stderr,
					"Error: Redo message failed, no matching message type for %d\n", msg.msgType);
		}
		msgSize = msg.getSerializedSize();
		printf("msgSize: %d\n", msgSize);
		msgOffset += msgSize;
		readBytes -= msgSize;
		printf("readBytes: %d\n", readBytes);
		memmove(msgBuffer, msgBuffer + msgSize, readBytes);
		memset(msgBuffer + readBytes, 0, BUFFERLENGTH - readBytes);
		if (readBytes == 0)
		{
			break;
		}
	}
	close(logFd);
	// free(msgBuffer);
	// msgBuffer = NULL;
	return offset;
}

/*
 * A function that send the tableFile content to the secondary in recovery
 * Input: tableName, the name of the table
 * 		  fd, the file descriptor of the secondary
 * Return: true if the table files are sent successfully
 * 			false otherwise
 */
bool sendTableFiles(std::string tableName, int secondaryFd)
{
	std::string tableDir = path + "/" + tableName;
	for (const auto &entry : fs::directory_iterator(tableDir))
	{
		std::string filePath = entry.path();
		std::string fileName = tableName + "/" + entry.path().filename().string();
		int fileFd = open(filePath.c_str(), O_RDONLY);
		if (fileFd < 0)
		{
			printf("Cannot open file %s: %s\n", filePath.c_str(), strerror(errno));
			return false;
		}
		if (verbose)
		{
			printf("Primary sending file %s\n", fileName.c_str());
		}

		lseek(fileFd, 0, SEEK_SET);
		char buffer[CONTENTLENGTH];
		backendMessage dataFileRsp = backendMessage(backendMessage::DataFileRsp, "", 1);
		while (true)
		{
			memset(buffer, 0, CONTENTLENGTH);
			int readBytes = read(fileFd, buffer, CONTENTLENGTH);
			if (readBytes < 0)
			{
				printf("Error in recovery read from table %s at primary: %s\n", tableName.c_str(), strerror(errno));
				return false;
			}
			if (readBytes == 0)
			{
				printf("End of file\n");
				break;
			}
			std::string content(buffer, readBytes);
			dataFileRsp.setDataFileRspMsg(fileName, content);
			std::vector<char> rspBuffer;
			dataFileRsp.serialize(rspBuffer);
			write(secondaryFd, rspBuffer.data(), rspBuffer.size());
		}
		close(fileFd);
	}
	return true;
}

/*
 * A function that deletes outdated files in a directory
 * Input: dir, the directory to clean up
 * Return: true if the files are deleted successfully
 * 			false otherwise
 */
bool rmOutdatedFiles(std::string dir)
{
	try
	{
		for (const auto &entry : fs::directory_iterator(dir))
		{
			if (fs::is_regular_file(entry))
			{
				fs::remove(entry);
			}
		}
	}
	catch (fs::filesystem_error &e)
	{
		printf("Filesystem Error: %s\n", e.what());
		return false;
	}
	catch (std::exception &e)
	{
		printf("Error: %s\n", e.what());
		return false;
	}
	return true;
}

/*
 * A function that cleans up the msgId maps
 * Input: msgId, the msgId to clean up
 */
void cleanUpMsgIdMaps(std::string msgId)
{
	msgId2ClientFd.erase(msgId);
	msgId2SourceIpPort.erase(msgId);
	ackCounter.erase(msgId);
	msgId2Index.erase(msgId);
}

/*
 * A function to send back a response
 * Input: index, the index of the message in the fds array
 */
void deliverRsp(int index)
{
	if (msgId2SourceIpPort.find(msgIds[index]) != msgId2SourceIpPort.end())
	{
		if (verbose)
		{
			std::cout << "Deliver ACK to " << msgId2SourceIpPort.at(msgIds[index]) << std::endl;
		}
		backendMessage ackMsg = backendMessage(backendMessage::Ack,
											   msgIds[index], 1);
		ackMsg.setAckMsg(msgIds[index], backendMessage::responseType::OK);
		forwardToPeers(ackMsg, msgId2SourceIpPort.at(msgIds[index]));
		cleanUpMsgIdMaps(msgIds[index]);
	}
	else
	{
		if (verbose)
		{
			std::cout << "Deliver RSP to client" << std::endl;
		}
		std::vector<char> rspBuffer;
		backendMessage rspMsg = backendMessage(backendMessage::Rsp,
											   msgIds[index], 1);
		rspMsg.setRspMsg(backendMessage::responseType::OK,
						 "Command implemented");
		rspMsg.serialize(rspBuffer);
		int bytes = write(msgId2ClientFd[msgIds[index]], rspBuffer.data(),
						  rspBuffer.size());
		cleanUpMsgIdMaps(msgIds[index]);
	}
}

/*
 * A function to process the queued messages.
 * It is called when the worker is done with the checkpointing.
 */
void clearQueue()
{
	pthread_mutex_lock(&outQueueLock);
	for (auto it = outQueue.begin(); it != outQueue.end(); ++it)
	{
		backendMessage msg = std::get<0>(*it);
		std::string ipPort = std::get<1>(*it);
		forwardToPeers(msg, ipPort);
	}
	outQueue.clear();
	pthread_mutex_unlock(&outQueueLock);
	while (true)
	{
		printf("Processing queued messages during checkpointing\n");
		pthread_mutex_lock(&queueLock);
		if (queue.size() == 0)
		{
			// queue empty
			isCheckpointing = false;
			pthread_mutex_unlock(&queueLock);
			if (verbose)
			{
				printf("Finished processing queued messages during checkpointing\n");
				printf("isCheckpointing?: %d\n", isCheckpointing);
			}
			return;
		}

		std::tuple<backendMessage, int, int, off_t> currItem = queue.front();
		queue.pop_front();
		pthread_mutex_unlock(&queueLock);
		performRequest(std::get<0>(currItem), std::get<1>(currItem),
					   std::get<2>(currItem), std::get<3>(currItem));
	}
}

/*
 * A function to print the current time
 */
void printTime()
{
	auto now = std::chrono::high_resolution_clock::now();
	auto now_c = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

	std::cout << "Current time: "
			  << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S")
			  << '.' << std::setfill('0') << std::setw(3) << milliseconds.count() << std::endl;
}

/*
 * A function to rebuild the offset map
 */
bool rebuildOffsets(std::map<std::string, std::map<std::string, uint64_t>> *currOffsets,
					pthread_mutex_t *currOffsetLock, std::string rowName, std::string tableName)
{
	if (verbose)
	{
		std::cout << "Rebuilding offsets" << std::endl;
		std::cout << "Row name: " << rowName << std::endl;
		std::cout << "Table name: " << tableName << std::endl;
	}
	pthread_mutex_lock(currOffsetLock);

	// row already recovered
	if (currOffsets->find(rowName) != currOffsets->end())
	{
		if (verbose)
		{
			std::cout << "Row already recovered" << std::endl;
			for (auto it = currOffsets->at(rowName).begin(); it != currOffsets->at(rowName).end(); ++it) {
				std::cout << "colname: " << it->first << " offset: " << it->second << std::endl;
		}
		}
		pthread_mutex_unlock(currOffsetLock);
		return true;
	}

	// row not recovered
	pthread_mutex_unlock(currOffsetLock);

	printf("Rebuilding offsets for %s\n", rowName.c_str());
	if (tableRowMap.at(tableName).find(rowName) == tableRowMap.at(tableName).end())
	{
		// row not in table map
		if (verbose)
		{
			std::cout << "Row not in table map" << std::endl;
		}
		return false;
	}

	// row in table map
	// on disk
	if (verbose)
	{
		std::cout << "Row in table map" << std::endl;
	}
	std::map<std::string, uint64_t> rowMap;
	pthread_mutex_lock(currOffsetLock);
	currOffsets->insert({rowName, rowMap});
	pthread_mutex_unlock(currOffsetLock);

	// get file fd
	std::string fileName = path + "/" + tableName + "/" + rowName + ".txt";
	if (verbose)
		std::cerr << "Rebuilding: File name: " << fileName << "\n";

	int fd = open(fileName.c_str(), O_RDONLY);
	off_t fileOffset = 0;
	off_t fileSize = lseek(fd, 0, SEEK_END);

	while (fileOffset < fileSize)
	{
		lseek(fd, fileOffset, SEEK_SET);
		// get the column
		char colBuffer[32];
		if (read(fd, colBuffer, 32) < 0)
		{
			printf("5324: Error: Cannot read column name in row %s\n", rowName.c_str());
			return false;
		}
		std::string colName(colBuffer, 32);
		fileOffset += 32;

		// write in the offset
		pthread_mutex_lock(currOffsetLock);
		currOffsets->at(rowName).insert({colName, fileOffset - 32});
		pthread_mutex_unlock(currOffsetLock);
		lseek(fd, fileOffset + 1, SEEK_SET);
		fileOffset += 1;

		// get the size
		char sizeBuffer[32];
		if (read(fd, sizeBuffer, 32) < 0)
		{
			printf("5341 Error: Cannot read size in row %s for column %s\n", rowName.c_str(), colName.c_str());
			return false;
		}
		// find space
		int spaceIndex = 0;
		while (spaceIndex < 32)
		{
			if (sizeBuffer[spaceIndex] == ' ')
			{
				break;
			}
			spaceIndex++;
		}
		std::string sizeStr(sizeBuffer, spaceIndex);
		off_t cellSize = (off_t)std::stoul(sizeStr);

		// go to the next offset
		fileOffset += spaceIndex + 1 + cellSize;
	}
	if (verbose) {
		printf("Rebuilding offsets for row %s in table %s done\n", rowName.c_str(), tableName.c_str());
		for (auto it = currOffsets->at(rowName).begin(); it != currOffsets->at(rowName).end(); ++it) {
			std::cout << "colname: " << it->first << " offset: " << it->second << std::endl;
		}
	}
	return true;
}

/*
 * A function to load the file names stored on disk
 */

void listOnDiskFiles()
{
	std::string userInfoTable = path + "/UserInfoTable";
	std::string userFileTable = path + "/UserFileTable";
	std::string inboxTable = path + "/InboxTable";
	tableRowMap.insert({"UserInfoTable", std::set<std::string>()});
	tableRowMap.insert({"UserFileTable", std::set<std::string>()});
	tableRowMap.insert({"InboxTable", std::set<std::string>()});
	for (const auto &entry : fs::directory_iterator(userInfoTable))
	{
		std::string filePath = entry.path();
		if (fs::is_regular_file(entry))
		{
			printf("UserInfoTable filePath: %s", filePath.c_str());
			filePath = filePath.substr(filePath.find_last_of("/\\") + 1);
			filePath = filePath.substr(0, filePath.find_last_of("."));
			tableRowMap["UserInfoTable"].insert(filePath);
		}
	}
	for (const auto &entry : fs::directory_iterator(userFileTable))
	{
		std::string filePath = entry.path();
		if (fs::is_regular_file(entry))
		{
			printf("UserFileTable filePath: %s", filePath.c_str());
			filePath = filePath.substr(filePath.find_last_of("/\\") + 1);
			filePath = filePath.substr(0, filePath.find_last_of("."));
			tableRowMap["UserFileTable"].insert(filePath);
		}
	}
	for (const auto &entry : fs::directory_iterator(inboxTable))
	{
		std::string filePath = entry.path();
		if (fs::is_regular_file(entry))
		{
			printf("InboxTable filePath: %s", filePath.c_str());
			filePath = filePath.substr(filePath.find_last_of("/\\") + 1);
			filePath = filePath.substr(0, filePath.find_last_of("."));
			tableRowMap["InboxTable"].insert(filePath);
		}
	}
	// print tableRowMap
	if (verbose) {
		printf("Table row map\n");
		for (auto it = tableRowMap.begin(); it != tableRowMap.end(); ++it) {
			std::cout << it->first << std::endl;
			for (auto it2 = it->second.begin(); it2 != it->second.end(); ++it2) {
				std::cout << *it2 << std::endl;
			}
		}
	}
}
