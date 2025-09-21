#include <string>
#include "backendMessage.h"

void computeDigest(char *data, int dataLengthBytes, unsigned char *digestBuffer);
std::string computeHash(const std::string &data);
std::string getCurrentTime();
void write_to_corrdinator(std::string source, backendMessage::requestType req_type, std::string table_name, std::string row_name, std::string col_name, std::string value_to_match, std::string new_value, int sockfd);
void write_to_kvs(std::string source, backendMessage::requestType req_type, std::string table_name, std::string row_name, std::string col_name, std::string value_to_match, std::string new_value, int sockfd);
int redir_from_kvs(int sockfd);
struct rsp_return rsp_from_kvs(int sockfd);
int connect_to_kvs(std::string source, backendMessage::requestType req_type, std::string tablename, std::string username, std::string colkey, std::string data);
std::string retr(std::string user_email, std::string content_hash);
backendMessage::responseType dele(std::string user_email, std::string content_hash);
struct uidl_return extract_uidl_info(std::string buf_str, std::string content_hash);
std::vector<struct uidl_return> uidl(std::string user_email);
// output functions
void output_354_input(int comm_fd, bool is_debug);

void output_550_unavailable(int comm_fd, bool is_debug);

void output_cmd_ooo(int comm_fd, bool is_debug);

void output_cmd_unrecognized(int comm_fd, bool is_debug);
void output_cmd_syntax_error(int comm_fd, bool is_debug);

void output_email_syntax_error(int comm_fd, bool is_debug);

void output_250_ok(int comm_fd, bool is_debug);

void output_250_localhost(int comm_fd, bool is_debug);

int send_kvs_emails(int comm_fd, std::string sender_email, std::string recipient_email, std::string data_buffer);

int write_emails(int comm_fd, std::string sender_email, std::vector<std::string> recipient_email_list, std::string data_buffer);