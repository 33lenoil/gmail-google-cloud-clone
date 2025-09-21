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
#include "smtpserver.h"

#define FD_LIST_SIZE 10000
#define MAX_ACTIVE_CONN 100
#define BUFFER_SIZE 4096

// state for smtp
enum class SMTP_State
{
    WAIT_HELO,
    WAIT_MAIL_FROM,
    WAIT_RCPT_TO,
    WAIT_DATA
};

struct rsp_return
{
    std::string content;
    backendMessage::responseType rsp_type;
};

int active_conn;
pthread_mutex_t active_conn_mutex;
bool is_debug;
volatile int comm_fd_list[FD_LIST_SIZE] = {0};
volatile bool shutting_down = false;
std::vector<pthread_t> thread_id_list;
std::string directory;
std::unordered_map<std::string, pthread_mutex_t> user_mutex_map;
// mutex for updating the mutex in the user_mutex_map
pthread_mutex_t map_mutex;


// quit the connection
void handle_quit(int comm_fd, bool is_debug)
{
    char response[] = "221 localhost Service closing transmission channel\r\n";
    if (is_debug)
    {
        fprintf(stderr, "[%d] S: %s\n", comm_fd, response);
    }
    write(comm_fd, response, strlen(response));
    close(comm_fd);
    if (is_debug)
    {
        fprintf(stderr, "[%d] Connection closed\n", comm_fd);
    }
    pthread_mutex_lock(&active_conn_mutex);
    active_conn -= 1;
    pthread_mutex_unlock(&active_conn_mutex);
    pthread_exit(NULL);
}

// handle ctrl C
void sigint_handler(int sig)
{
    shutting_down = true;
    for (int i = 0; i < FD_LIST_SIZE; i++)
    {
        if (comm_fd_list[i] != 0)
        {
            // set each connection to non-blocking
            fcntl(comm_fd_list[i], F_SETFL, O_NONBLOCK);
            char response[] = "221 localhost Service closing transmission channel\r\n";
            write(comm_fd_list[i], response, strlen(response));
            close(comm_fd_list[i]);
        }
    }

    // cancel all the threads
    for (int i = 0; i < thread_id_list.size(); i++)
    {
        pthread_cancel(thread_id_list[i]);
    }
    // join all the threads
    for (int i = 0; i < thread_id_list.size(); i++)
    {
        pthread_join(thread_id_list[i], NULL);
    }
    exit(0);
}

void *worker(void *arg)
{
    int comm_fd = *(int *)arg;
    delete ((int *)arg);
    char buf[1024] = "";
    SMTP_State state = SMTP_State::WAIT_HELO;

    std::string sender_email; // format: username@localhost

    std::vector<std::string> recipient_email_list; // format: username

    std::string data_buffer; // for holding email data context

    char read_buf[100];
    ssize_t r_bytes;
    while ((r_bytes = read(comm_fd, read_buf, 100)) > 0)
    {
        read_buf[r_bytes] = '\0';
        strcat(buf, read_buf);
        // check if the buffer contains the string "\r\n"
        while (strstr(buf, "\r\n") != NULL)
        {
            std::string buf_str(buf);
            size_t pos = buf_str.find("\r\n");
            std::string firstPart = buf_str.substr(0, pos + 2);
            const char *first_line = firstPart.c_str();

            if (is_debug)
            {
                fprintf(stderr, "[%d] C: %s\n", comm_fd, first_line);
            }
            if (state == SMTP_State::WAIT_HELO)
            {
                if (strncasecmp(first_line, "HELO", 4) == 0 && strcasecmp(first_line, "HELO\r\n") != 0 && strcasecmp(first_line, "HELO \r\n") != 0)
                {
                    output_250_localhost(comm_fd, is_debug);
                    state = SMTP_State::WAIT_MAIL_FROM;
                }
                else if (strncasecmp(first_line, "MAIL FROM:", 10) == 0 ||
                         strncasecmp(first_line, "RCPT TO:", 8) == 0 ||
                         strcasecmp(first_line, "DATA\r\n") == 0 ||
                         strcasecmp(first_line, "QUIT\r\n") == 0 ||
                         strcasecmp(first_line, "RSET\r\n") == 0 ||
                         strcasecmp(first_line, "NOOP\r\n") == 0)
                {
                    // out of order
                    output_cmd_ooo(comm_fd, is_debug);
                }
                else
                {
                    output_cmd_unrecognized(comm_fd, is_debug);
                }
            }
            else if (state == SMTP_State::WAIT_MAIL_FROM)
            {
                // empty the sender email buffer if it's not empty
                sender_email.clear();

                // EMTPY the recipient email list
                recipient_email_list.clear();

                // empty the data string
                data_buffer.clear();

                if (strncasecmp(first_line, "MAIL FROM:", 10) == 0)
                {
                    std::string first_line_str(first_line);

                    // Find the start and end positions of the email address within the angle brackets
                    size_t start_pos = first_line_str.find("<") + 1;
                    size_t end_pos = first_line_str.find(">");

                    if (start_pos - 1 == std::string::npos || end_pos == std::string::npos)
                    {
                        output_email_syntax_error(comm_fd, is_debug);
                    }
                    else
                    {
                        // Extract the email address
                        sender_email = first_line_str.substr(start_pos, end_pos - start_pos);

                        size_t at_pos = sender_email.find("@");
                        std::string username = sender_email.substr(0, at_pos);
                        std::string domain = sender_email.substr(at_pos + 1);

                        // check if username and domain are not null
                        if (username.empty() || domain.empty())
                        {
                            output_email_syntax_error(comm_fd, is_debug);
                        }
                        else
                        {
                            output_250_ok(comm_fd, is_debug);
                            state = SMTP_State::WAIT_RCPT_TO;
                        }
                    }
                }
                else if (strncasecmp(first_line, "HELO", 4) == 0 && strcasecmp(first_line, "HELO\r\n") != 0 && strcasecmp(first_line, "HELO \r\n") != 0)
                {
                    output_250_localhost(comm_fd, is_debug);
                    state = SMTP_State::WAIT_MAIL_FROM;
                }
                else if (strncasecmp(first_line, "RCPT TO:", 8) == 0 ||
                         strcasecmp(first_line, "DATA\r\n") == 0)
                {
                    output_cmd_ooo(comm_fd, is_debug);
                }
                else if (strcasecmp(first_line, "QUIT\r\n") == 0)
                {
                    handle_quit(comm_fd, is_debug);
                }
                else if (strcasecmp(first_line, "RSET\r\n") == 0)
                {
                    output_250_ok(comm_fd, is_debug);
                    state = SMTP_State::WAIT_MAIL_FROM;
                }
                else if (strcasecmp(first_line, "NOOP\r\n") == 0)
                {
                    output_250_ok(comm_fd, is_debug);
                }
                else
                {
                    output_cmd_unrecognized(comm_fd, is_debug);
                }
            }
            else if (state == SMTP_State::WAIT_RCPT_TO)
            {
                if (strncasecmp(first_line, "RCPT TO:", 8) == 0)
                {

                    std::string first_line_str(first_line);

                    size_t start_pos = first_line_str.find("<") + 1;
                    size_t end_pos = first_line_str.find(">");

                    if (start_pos - 1 == std::string::npos || end_pos == std::string::npos)
                    {
                        output_email_syntax_error(comm_fd, is_debug);
                    }
                    else
                    {
                        std::string email = first_line_str.substr(start_pos, end_pos - start_pos);

                        size_t at_pos = email.find("@");
                        std::string username = email.substr(0, at_pos);
                        std::string domain = email.substr(at_pos + 1);

                        std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

                        // if (domain == "localhost" )&& file_exists(directory + "/" + username + ".mbox"))
                        // {
                        output_250_ok(comm_fd, is_debug);
                        recipient_email_list.push_back(email);
                        // }
                        // else
                        // {
                        //   output_550_unavailable(comm_fd, is_debug);
                        // }
                        state = SMTP_State::WAIT_RCPT_TO; // can keep waiting for recipients
                    }
                }
                else if (strcasecmp(first_line, "DATA\r\n") == 0) // stop waiting for recipients now and move to accepting data
                {
                    output_354_input(comm_fd, is_debug);
                    state = SMTP_State::WAIT_DATA;
                }
                else if (strncasecmp(first_line, "MAIL FROM:", 10) == 0 ||
                         (strncasecmp(first_line, "HELO", 4) == 0 && strcasecmp(first_line, "HELO\r\n") != 0 && strcasecmp(first_line, "HELO \r\n") != 0))
                {
                    output_cmd_ooo(comm_fd, is_debug);
                }
                else if (strcasecmp(first_line, "QUIT\r\n") == 0)
                {
                    handle_quit(comm_fd, is_debug);
                }
                else if (strcasecmp(first_line, "RSET\r\n") == 0)
                {
                    output_250_ok(comm_fd, is_debug);
                    state = SMTP_State::WAIT_MAIL_FROM;
                }
                else if (strcasecmp(first_line, "NOOP\r\n") == 0)
                {
                    output_250_ok(comm_fd, is_debug);
                }
                else
                {
                    output_cmd_unrecognized(comm_fd, is_debug);
                }
            }
            else if (state == SMTP_State::WAIT_DATA)
            {
                // compare the first_line to "."
                if (strcmp(first_line, ".\r\n") == 0)
                {
                    // write_to_file(comm_fd, sender_email, recipient_email_list, data_buffer);
                    write_emails(comm_fd, sender_email, recipient_email_list, data_buffer);
                    state = SMTP_State::WAIT_MAIL_FROM;
                }
                else
                {
                    std::string first_line_str(first_line);
                    data_buffer.append(first_line_str);
                }
            }
            // remove the processed command form the buf

            off_t offset = strlen(first_line);

            std::string strBuffer(buf);
            std::string substring = strBuffer.substr(offset);
            const char *new_buffer = substring.c_str();
            strcpy(buf, new_buffer);
        }
        // clear the read buffer
        memset(read_buf, 0, 100);
    }
}

int main(int argc, char *argv[])
{

    // Parse command-line arguments
    int arg_p;
    int port = 2500;
    is_debug = false;
    active_conn = 0;

    while ((arg_p = getopt(argc, argv, "avp:")) != -1)
    {
        switch (arg_p)
        {
        case 'p':
            port = atoi(optarg);
            break;
        case 'a':
            fprintf(stderr, "Author: Jiening Li / jiening\r\n");
            exit(0);
            break;
        case 'v':
            is_debug = true;
            break;
        default:
            break;
        }
    }
    //   if (optind < argc)
    //   {
    //     directory = argv[optind];
    //   }
    //   else
    //   {
    //     fprintf(stderr, "No directory specified.\n");
    //     return EXIT_FAILURE;
    //   }

    pthread_mutex_init(&active_conn_mutex, NULL);
    pthread_mutex_init(&map_mutex, NULL);

    int listen_fd = socket(PF_INET, SOCK_STREAM, 0);
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htons(INADDR_ANY); // TODO?
    servaddr.sin_port = htons(port);
    bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));
    listen(listen_fd, 10);

    // register signal handler
    signal(SIGINT, sigint_handler);

    while (true)
    {

        // keep track of the active connection
        pthread_mutex_lock(&active_conn_mutex);
        if (active_conn >= MAX_ACTIVE_CONN)
        {
            pthread_mutex_unlock(&active_conn_mutex);
            continue;
        }
        else
        {
            active_conn += 1;
        }

        pthread_mutex_unlock(&active_conn_mutex);
        struct sockaddr_in clientaddr;
        socklen_t clientaddrlen = sizeof(clientaddr);
        int *fd = (int *)malloc(sizeof(int));
        *fd = accept(listen_fd, (struct sockaddr *)&clientaddr, &clientaddrlen);
        if (is_debug)
        {
            fprintf(stderr, "[%d] New connection\n", *fd);
        }

        // close new connections that may be added to the array so sigint handler doesn't need to handle
        if (shutting_down)
        {
            char response[] = "221 localhost Service closing transmission channel\r\n";
            write(*fd, response, strlen(response));
            close(*fd);
        }

        // add the fd to the global fd list
        for (int i = 0; i < FD_LIST_SIZE; i++)
        {
            if (comm_fd_list[i] == 0)
            {
                comm_fd_list[i] = *fd;
                break;
            }
        }

        char greeting[] = "220 localhost service ready\r\n";
        write(*fd, greeting, strlen(greeting));
        pthread_t thread;
        pthread_create(&thread, NULL, worker, fd);
        thread_id_list.push_back(thread);
    }
    for (int i = 0; i < thread_id_list.size(); i++)
    {
        // join all the thread in the thread_id_list
        pthread_join(thread_id_list[i], NULL);
    }

    pthread_mutex_destroy(&active_conn_mutex);
    pthread_mutex_destroy(&map_mutex);
    // delete the mutex in the user_mutex_map
    for (auto it = user_mutex_map.begin(); it != user_mutex_map.end(); it++)
    {
        pthread_mutex_destroy(&it->second);
    }

    return 0;
}