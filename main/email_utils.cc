

#include <string>
#include "backendMessage.h"
#include "email_utils.h"
#include <sys/socket.h>
#include <arpa/inet.h>
#include <cstring>
#include <cmath>
#include <openssl/md5.h>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>
#include <vector>
#include "smtpclient.h"

#define BUFFER_SIZE 4096
#define SRC_EMAIL "email"

struct uidl_return
{
    std::string hash_id;
    std::string subject;
    std::string sender;
    std::string date;
};

struct rsp_return
{
    std::string content;
    backendMessage::responseType rsp_type;
};

void computeDigest(char *data, int dataLengthBytes, unsigned char *digestBuffer)
{
    /* The digest will be written to digestBuffer, which must be at least MD5_DIGEST_LENGTH bytes long */

    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, data, dataLengthBytes);
    MD5_Final(digestBuffer, &c);
}

std::string computeHash(const std::string &data)
{
    unsigned char digestBuffer[MD5_DIGEST_LENGTH];
    computeDigest((char *)data.c_str(), data.length(), digestBuffer);
    std::stringstream hex_ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++)
    {
        hex_ss << std::hex << std::setw(2) << std::setfill('0') << (int)digestBuffer[i];
    }
    return hex_ss.str();
}

// time formatting: weekday month day hour:minute:second year

std::string getCurrentTime()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_clock = std::chrono::system_clock::to_time_t(now);
    // use localtime zone
    std::tm break_down_tm_now = *std::localtime(&now_clock);
    std::stringstream timebuffer;
    timebuffer << std::put_time(&break_down_tm_now, "%a %b %d %H:%M:%S %Y");
    return timebuffer.str();
}

// todo multiple chunks

void write_to_corrdinator(std::string source, backendMessage::requestType req_type, std::string table_name, std::string row_name, std::string col_name, std::string value_to_match, std::string new_value, int sockfd)
{
    std::vector<char> buffer;
    std::string msg_id = computeHash(source + getCurrentTime() + new_value);
    backendMessage msg = backendMessage(backendMessage::Req, msg_id, 1); // create a Req message with msgId = 1, and not the last packet
    msg.setReqMsg(req_type, table_name, row_name, col_name, "", "");
    msg.serialize(buffer); // serialize the message to buffer
    // print sockfd
    fprintf(stderr, "sockfd: %d\n", sockfd);
    int w_bytes = write(sockfd, buffer.data(), buffer.size());
    fprintf(stderr, "write bytes: %d\n", w_bytes);
    if (w_bytes == -1)
    {
        fprintf(stderr, "error writing to socket\n");
    };
    fprintf(stderr, "finish functions to write to kvs\n");
    return;
}

void write_to_kvs(std::string source, backendMessage::requestType req_type, std::string table_name, std::string row_name, std::string col_name, std::string value_to_match, std::string new_value, int sockfd)
{

    std::vector<char> buffer;
    std::string msg_id = computeHash(source + getCurrentTime() + new_value);
    // split the new_value in chunks of 4000, and send them one by one
    int chunks_cnt = std::ceil(new_value.size() / 4000.0);
    fprintf(stderr, "chunks count: %d\n", chunks_cnt);

    // chunks_cnt = 1; req, msgid, 1

    // chunks_cnt != 1;
    // a. req, msgid, 0 - i = 0
    // b. append, msgid, 0 - 0 < i < chunks - 1
    // c. append, msgid, 1 - i = chunks - 1

    if (chunks_cnt == 1 || chunks_cnt == 0) // chunks_cnt = 0 get
    {
        backendMessage msg = backendMessage(backendMessage::Req, msg_id, 1); // create a Req message with msgId = 1, and not the last packet
        msg.setReqMsg(req_type, table_name, row_name, col_name, value_to_match, new_value);
        msg.serialize(buffer); // serialize the message to buffer
        // print sockfd
        fprintf(stderr, "sockfd: %d\n", sockfd);
        int w_bytes = write(sockfd, buffer.data(), buffer.size());
        fprintf(stderr, "write bytes: %d\n", w_bytes);
        if (w_bytes == -1)
        {
            fprintf(stderr, "error writing to socket\n");
        };
        fprintf(stderr, "finish functions to write to kvs\n");
        return;
    }
    else
    {
        for (int i = 0; i < chunks_cnt; i++)
        {
            backendMessage msg;
            std::string chunk = new_value.substr(i * 4000, 4000);
            if (i == 0)
            {
                msg = backendMessage(backendMessage::Req, msg_id, 0);
                msg.setReqMsg(req_type, table_name, row_name, col_name, value_to_match, chunk);
                buffer.clear();
                msg.serialize(buffer); // serialize the message to buffer
                int w_bytes = write(sockfd, buffer.data(), buffer.size());
                fprintf(stderr, "write bytes: %d\n", w_bytes);
                if (w_bytes == -1)
                {
                    fprintf(stderr, "error writing to socket\n");
                };
            }
            else if (i == chunks_cnt - 1)
            {
                int new_fd = connect_to_kvs(source, req_type, table_name, row_name, col_name, value_to_match);
                msg = backendMessage(backendMessage::Append, msg_id, 1);
                msg.setAppendMsg(table_name, row_name, col_name, chunk);
                buffer.clear();
                msg.serialize(buffer); // serialize the message to buffer
                int w_bytes = write(new_fd, buffer.data(), buffer.size());
                fprintf(stderr, "write bytes: %d\n", w_bytes);
                if (w_bytes == -1)
                {
                    fprintf(stderr, "error writing to socket\n");
                };
                close(new_fd);
            }
            else
            {
                int new_fd = connect_to_kvs(source, req_type, table_name, row_name, col_name, value_to_match);
                msg = backendMessage(backendMessage::Append, msg_id, 0);
                msg.setAppendMsg(table_name, row_name, col_name, chunk);
                buffer.clear();
                msg.serialize(buffer); // serialize the message to buffer
                int w_bytes = write(new_fd, buffer.data(), buffer.size());
                fprintf(stderr, "write bytes: %d\n", w_bytes);
                if (w_bytes == -1)
                {
                    fprintf(stderr, "error writing to socket\n");
                };
                close(new_fd);
            }
            // std::string chunk = new_value.substr(i * 4000, 4000);
            // msg.setReqMsg(req_type, table_name, row_name, col_name, value_to_match, chunk); // value to match should be a chunk

            fprintf(stderr, "finish functions to write to kvs\n");
        }
    }
}

int redir_from_kvs(int sockfd) // only in one chunk
{
    char *inBuf = (char *)malloc(BUFFER_SIZE);
    int bytesRead = read(sockfd, inBuf, BUFFER_SIZE);
    backendMessage msg = backendMessage();
    msg.deserialize(inBuf, bytesRead);
    // msg.printMsg();
    backendMessage::RedirMsg redirMsg = msg.getRedirMsg();
    redirMsg.printMsg();
    std::string ipPort = redirMsg.ipPort;
    std::string ip = ipPort.substr(0, ipPort.find(":"));
    int port = std::stoi(ipPort.substr(ipPort.find(":") + 1));
    free(inBuf);
    return port; // todo might need IP?
}

struct rsp_return rsp_from_kvs(int sockfd)
{
    // set a timeout
    struct rsp_return full_rsp;
    fprintf(stderr, "start reading response from kvs\n");
    full_rsp.content = "";
    while (true)
    {

        char *inBuf = (char *)malloc(BUFFER_SIZE);
        fprintf(stderr, "start reading\n");
        int read_bytes = read(sockfd, inBuf, BUFFER_SIZE);
        fprintf(stderr, "read bytes: %d\n", read_bytes);
        backendMessage msg = backendMessage();
        msg.deserialize(inBuf, read_bytes);
        // msg.printMsg();
        backendMessage::RspMsg rspMsg = msg.getRspMsg();
        rspMsg.printMsg();
        full_rsp.rsp_type = rspMsg.status;
        full_rsp.content += rspMsg.content;
        free(inBuf);
        // print(msg.isEnd)
        fprintf(stderr, "isEnd: %d\n", msg.isEnd);
        if (msg.isEnd == 1) // 1 means message end
        {
            break;
        }
    }
    // fprintf(stderr, "full response: %s\n", full_rsp.content.c_str());
    return full_rsp;
}

int connect_to_kvs(std::string source, backendMessage::requestType req_type, std::string tablename, std::string username, std::string colkey, std::string data)
{
    int smtp_bmaster_fd = socket(PF_INET, SOCK_STREAM, 0);
    struct sockaddr_in bmasteraddr;
    bzero(&bmasteraddr, sizeof(bmasteraddr));
    bmasteraddr.sin_family = AF_INET;
    bmasteraddr.sin_addr.s_addr = htons(INADDR_ANY); // todo host address
    bmasteraddr.sin_port = htons(10000);             // todo make sure
    if (connect(smtp_bmaster_fd, (struct sockaddr *)&bmasteraddr, sizeof(bmasteraddr)) < 0)
    {
        fprintf(stderr, "Error connecting to the backend master\n");
        exit(1);
    }
    fprintf(stderr, "connected to backend master\n");
    write_to_corrdinator(source, req_type, tablename, username, colkey, "", data, smtp_bmaster_fd);
    // see whether buf ia a number, stored it in port
    int backend_worker_port = redir_from_kvs(smtp_bmaster_fd);
    fprintf(stderr, "backend worker port: %d\n", backend_worker_port);
    close(smtp_bmaster_fd);
    int stmp_bworker_fd = socket(PF_INET, SOCK_STREAM, 0);
    struct sockaddr_in bworkeraddr;
    bzero(&bworkeraddr, sizeof(bworkeraddr));
    bworkeraddr.sin_family = AF_INET;
    bworkeraddr.sin_addr.s_addr = htons(INADDR_ANY); // todo host address
    bworkeraddr.sin_port = htons(backend_worker_port);
    if (connect(stmp_bworker_fd, (struct sockaddr *)&bworkeraddr, sizeof(bworkeraddr)) < 0)
    {
        fprintf(stderr, "Error connecting to the backend worker\n");
        exit(1);
    }
    fprintf(stderr, "smtp_bworker_fd: %d\n", stmp_bworker_fd);
    return stmp_bworker_fd;
}

std::string retr(std::string user_email, std::string content_hash)
{
    int fd = connect_to_kvs(SRC_EMAIL, backendMessage::GET, "InboxTable", user_email, content_hash, "");
    write_to_kvs(SRC_EMAIL, backendMessage::GET, "InboxTable", user_email, content_hash, "", "", fd);
    struct rsp_return rsp = rsp_from_kvs(fd); // get the response
    if (rsp.rsp_type == backendMessage::OK)
    {
        return rsp.content;
    }
    close(fd);
    return "";
}

backendMessage::responseType dele(std::string user_email, std::string content_hash)
{
    int fd = connect_to_kvs(SRC_EMAIL, backendMessage::DELETE, "InboxTable", user_email, content_hash, "");
    write_to_kvs(SRC_EMAIL, backendMessage::DELETE, "InboxTable", user_email, content_hash, "", "", fd);
    struct rsp_return rsp = rsp_from_kvs(fd); // get the response
    close(fd);
    return rsp.rsp_type;
}

struct uidl_return extract_uidl_info(std::string buf_str, std::string content_hash)
{
    std::string subject;
    std::string sender;
    std::string date;

    fprintf(stderr, "extract buf_str: %s\n", buf_str.c_str());
    size_t subject_start_pos = buf_str.find("Subject: ") + 9;
    size_t subject_end_pos = buf_str.find("\n", subject_start_pos);
    subject = buf_str.substr(subject_start_pos, subject_end_pos - subject_start_pos);

    size_t header_start = buf_str.find("From ") + 5;
    size_t header_end = buf_str.find("\n", header_start);
    std::string header = buf_str.substr(header_start, header_end - header_start);
    size_t sender_start_pos = header.find("<") + 1;
    size_t sender_end_pos = header.find(">");
    sender = header.substr(sender_start_pos, sender_end_pos - sender_start_pos);

    size_t date_start_pos = sender_end_pos + 2;
    date = header.substr(date_start_pos);

    return {content_hash, subject, sender, date};
}

std::vector<struct uidl_return> uidl(std::string user_email)
{
    std::vector<struct uidl_return> uidl_info;
    int fd = connect_to_kvs(SRC_EMAIL, backendMessage::GETROW, "InboxTable", user_email, "", "");
    write_to_kvs(SRC_EMAIL, backendMessage::GETROW, "InboxTable", user_email, "", "", "", fd);
    rsp_return rsp = rsp_from_kvs(fd);
    std::string response = rsp.content; // get the response. // todo test
    backendMessage::responseType rsp_type = rsp.rsp_type;
    close(fd);
    if (rsp_type != backendMessage::OK)
    {   
        return uidl_info;
    }
    
    // split response by '\n'
    std::vector<std::string> content_hashes;
    std::stringstream ss(response);

    std::string line;
    while (std::getline(ss, line, '\n'))
    {
        content_hashes.push_back(line);
    }
    for (std::string content_hash : content_hashes)
    {
        std::string email_content = retr(user_email, content_hash);
        uidl_info.push_back(extract_uidl_info(email_content, content_hash));
    }
    // sort the uidl_info by date in descending order
    std::sort(uidl_info.begin(), uidl_info.end(), [](struct uidl_return a, struct uidl_return b)
              { return a.date > b.date; });
    for (struct uidl_return info : uidl_info)
    {
        fprintf(stderr, "content_hash: %s\n", info.hash_id.c_str());
        fprintf(stderr, "subject: %s\n", info.subject.c_str());
        fprintf(stderr, "sender: %s\n", info.sender.c_str());
        fprintf(stderr, "date: %s\n", info.date.c_str());
    }
    return uidl_info;
}

// output functions
void output_354_input(int comm_fd, bool is_debug)
{
    char response[] = "354 Start mail input; end with <CRLF>.<CRLF>\r\n";
    if (is_debug)
    {
        fprintf(stderr, "[%d] S: %s\n", comm_fd, response);
    }
    write(comm_fd, response, strlen(response));
}

void output_550_unavailable(int comm_fd, bool is_debug)
{
    char response[] = "550 Requested action not taken: mailbox unavailable\r\n";
    if (is_debug)
    {
        fprintf(stderr, "[%d] S: %s\n", comm_fd, response);
    }
    write(comm_fd, response, strlen(response));
}

void output_cmd_ooo(int comm_fd, bool is_debug)
{
    char response[] = "503 Bad sequence of commands\r\n";
    if (is_debug)
    {
        fprintf(stderr, "[%d] S: %s\n", comm_fd, response);
    }
    write(comm_fd, response, strlen(response));
}

void output_cmd_unrecognized(int comm_fd, bool is_debug)
{
    char response[] = "500 command unrecognized\r\n";
    if (is_debug)
    {
        fprintf(stderr, "[%d] S: %s\n", comm_fd, response);
    }
    write(comm_fd, response, strlen(response));
}

void output_cmd_syntax_error(int comm_fd, bool is_debug)
{
    char response[] = "500 Syntax error, command line too long\r\n";
    if (is_debug)
    {
        fprintf(stderr, "[%d] S: %s\n", comm_fd, response);
    }
    write(comm_fd, response, strlen(response));
}

void output_email_syntax_error(int comm_fd, bool is_debug)
{
    char response[] = "500 Syntax error with email address\r\n";
    if (is_debug)
    {
        fprintf(stderr, "[%d] S: %s\n", comm_fd, response);
    }
    write(comm_fd, response, strlen(response));
}

void output_250_ok(int comm_fd, bool is_debug)
{
    char response[] = "250 OK\r\n";
    if (is_debug)
    {
        fprintf(stderr, "[%d] S: %s\n", comm_fd, response);
    }
    write(comm_fd, response, strlen(response));
}

void output_250_localhost(int comm_fd, bool is_debug)
{
    char response[] = "250 localhost\r\n";
    if (is_debug)
    {
        fprintf(stderr, "[%d] S: %s\n", comm_fd, response);
    }
    write(comm_fd, response, strlen(response));
}

int send_kvs_emails(int comm_fd, std::string sender_email, std::string recipient_email, std::string data_buffer)
{
    bool is_debug = true;

    // get the domain of the recipient email
    size_t at_pos = recipient_email.find("@");
    std::string recp_user = recipient_email.substr(0, at_pos);

    std::string header = "From <" + sender_email + "> " + getCurrentTime() + "\n";
    std::string whole_email = header + data_buffer;
    std::string content_hash = computeHash(whole_email);
    // init username mutex in the map. todo: lock necessary?
    // pthread_mutex_lock(&map_mutex);
    // if (user_mutex_map.find(recipient_email) == user_mutex_map.end())
    // {
    //     pthread_mutex_t user_mutex;
    //     pthread_mutex_init(&user_mutex, NULL);
    //     user_mutex_map[recipient_email] = user_mutex;
    // }
    // pthread_mutex_unlock(&map_mutex);
    // pthread_mutex_lock(&user_mutex_map[recipient_email]);
    // to see whether the recp_user exists in the kvs
    int query_fd = connect_to_kvs("email", backendMessage::GETROW, "UserInfoTable", recp_user, "", "");
    write_to_kvs("email", backendMessage::GETROW, "UserInfoTable", recp_user, "", "", "", query_fd);
    struct rsp_return rsp = rsp_from_kvs(query_fd);
    close(query_fd);
    if (rsp.rsp_type == backendMessage::OK)
    {
        fprintf(stderr, "recp user exists; write to kvs\n");
        int fd_to_write = connect_to_kvs("email", backendMessage::PUT, "InboxTable", recp_user, content_hash, whole_email);
        write_to_kvs("email", backendMessage::PUT, "InboxTable", recp_user, content_hash, "", whole_email, fd_to_write);
        close(fd_to_write);
        output_250_ok(comm_fd, is_debug);
        return 0;
    }
    else{
        fprintf(stderr, "recp user does not exist\n");
        output_550_unavailable(comm_fd, is_debug);
        return -1;
    }
    // fprintf(stderr, "recp user: %s\n", recp_user.c_str());
    // std::string retr_result = retr(recp_user, content_hash);
    // fprintf(stderr, "retr result: %s\n", retr_result.c_str());
    // // uidl
    // std::vector<struct uidl_return> uidl_info = uidl(recp_user);
    // // print current time
    // fprintf(stderr, "current time: %s\n", getCurrentTime().c_str());
    // for (struct uidl_return info : uidl_info)
    // {
    //     fprintf(stderr, "content_hash: %s\n", info.hash_id.c_str());
    //     fprintf(stderr, "subject: %s\n", info.subject.c_str());
    //     fprintf(stderr, "sender: %s\n", info.sender.c_str());
    //     fprintf(stderr, "date: %s\n", info.date.c_str());
    // }
    // pthread_mutex_unlock(&user_mutex_map[recipient_email]);  
}

int write_emails(int comm_fd, std::string sender_email, std::vector<std::string> recipient_email_list, std::string data_buffer)
{
    int final_response_status = -1;
    bool is_debug = true;
    // iterate through the recipient email list
    for (int i = 0; i < recipient_email_list.size(); i++)
    {

        std::string recipient_email = recipient_email_list[i];
        // get the domain of the recipient email
        size_t at_pos = recipient_email.find("@");
        std::string domain = recipient_email.substr(at_pos + 1);
        std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);

        // check if the domain is localhost
        if (domain == "localhost")
        {
            if (send_kvs_emails(comm_fd, sender_email, recipient_email, data_buffer) == 0){
                final_response_status = 0;
            };
        }
        else
        {
            if (send_external_mails(sender_email, recipient_email, data_buffer) == 0){
                final_response_status = 0;
            }
        }
    }
    output_250_ok(comm_fd, is_debug);
    return final_response_status;
}
