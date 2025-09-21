#include <string>

std::string get_host(std::string domain);
int send_external_mails(std::string sender_email, std::string recipient_email, std::string data_buffer);