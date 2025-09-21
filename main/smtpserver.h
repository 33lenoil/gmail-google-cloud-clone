#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <string>
#include <signal.h>
#include <fcntl.h>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <sys/stat.h>
#include <unordered_map>
#include <sys/file.h>
#include <algorithm>
#include <openssl/md5.h>
#include "backendMessage.h"
#include "smtpclient.h"
#include "email_utils.h"




// quit the connection
void handle_quit(int comm_fd, bool is_debug);

// handle ctrl C
void sigint_handler(int sig);

void *worker(void *arg);