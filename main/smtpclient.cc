#include "smtpclient.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <resolv.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string>
#include <cstring>

#define BUFFER_SIZE 4096
#define SMTP_PORT 25

// bool is_debug = true; todo fix the is_debug

std::string get_host(std::string domain)
{
  u_char nsbuf[BUFFER_SIZE];
  char dispbuf[BUFFER_SIZE];
  ns_msg msg;
  ns_rr rr;
  int l = res_query(domain.c_str(), ns_c_in, ns_t_mx, nsbuf, sizeof(nsbuf));
  if (l < 0)
  {
    perror(domain.c_str());
  }
  else
  {
    ns_initparse(nsbuf, l, &msg);
    l = ns_msg_count(msg, ns_s_an);
    for (int i = 0; i < l; i++)
    {
      ns_parserr(&msg, ns_s_an, i, &rr);
      ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));
      printf("\t%s\n", dispbuf);
      if (ns_rr_type(rr) == ns_t_mx)
      {
        const u_char *mxData = ns_rr_rdata(rr);
        mxData += 2;
        if (ns_name_uncompress(ns_msg_base(*&msg), ns_msg_end(*&msg), mxData, dispbuf, sizeof(dispbuf)) != -1)
        {
          // printf("\tMail server: %s\n", dispbuf);
          break;
        }
      }
    }
  }
  // obtain ip address from dispbuf
  struct hostent *host = gethostbyname(dispbuf);
  if (host == NULL)
  {
    perror("gethostbyname");
    exit(1);
  }
  // fprintf(stderr, "Host name  : %s\n", host->h_name);
  // fprintf(stderr, "IP Address : %s\n", inet_ntoa(*(struct in_addr *)host->h_addr_list[0]));
  return inet_ntoa(*(struct in_addr *)host->h_addr_list[0]);
}

int send_external_mails(std::string sender_email, std::string recipient_email, std::string data_buffer)
{
  sender_email = "jiening@seas.upenn.edu"; // for sending out emails...
  bool is_debug = true; // todo fix this
  // todo: error handling.
  // get the recipient_email domain
  std::string recipient_domain = recipient_email.substr(recipient_email.find('@') + 1);
  std::string host_addr = get_host(recipient_domain);
  int port = SMTP_PORT;
  int sockfd;
  struct sockaddr_in dest;
  sockfd = socket(PF_INET, SOCK_STREAM, 0);
  dest.sin_family = AF_INET;
  dest.sin_port = htons(port);
  dest.sin_addr.s_addr = inet_addr(host_addr.c_str());
  if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) < 0)
  {
    fprintf(stderr, "Failed to connect to the server.\n");
    close(sockfd);
    return -1;
  }

  // read server response
  char buffer[BUFFER_SIZE];
  recv(sockfd, buffer, BUFFER_SIZE, 0);
  if (is_debug){
      printf("%s\n", buffer);
  }
  // reset buffer
  memset(buffer, 0, BUFFER_SIZE);

  // Send HELO command
  std::string helo = "HELO " + recipient_domain + "\r\n";
  send(sockfd, helo.c_str(), helo.size(), 0);
  recv(sockfd, buffer, BUFFER_SIZE, 0); // Read HELO response
    if (is_debug){
      printf("%s\n", buffer);
  }
    memset(buffer, 0, BUFFER_SIZE);

  // Send MAIL FROM command
  std::string mail_from = "MAIL FROM: <" + sender_email + ">\r\n";
  send(sockfd, mail_from.c_str(), mail_from.size(), 0);
  recv(sockfd, buffer, BUFFER_SIZE, 0); // Read MAIL FROM response
  if (is_debug){
      printf("%s\n", buffer);
  }
    memset(buffer, 0, BUFFER_SIZE);

  // Send RCPT TO command
  std::string rcpt_to = "RCPT TO: <" + recipient_email + ">\r\n";
  send(sockfd, rcpt_to.c_str(), rcpt_to.size(), 0);
  recv(sockfd, buffer, BUFFER_SIZE, 0); // Read RCPT TO response
  if (is_debug){
      printf("%s\n", buffer);
  }
    memset(buffer, 0, BUFFER_SIZE);

  // Send DATA command
  send(sockfd, "DATA\r\n", 6, 0);
  recv(sockfd, buffer, BUFFER_SIZE, 0); // Read DATA response
  if (is_debug){
      printf("%s\n", buffer);
  }
    memset(buffer, 0, BUFFER_SIZE);

  // Send email data
  std::string message = data_buffer + "\r\n.\r\n";
  send(sockfd, message.c_str(), message.size(), 0);
  recv(sockfd, buffer, BUFFER_SIZE, 0); // Read message response
  if (is_debug){
      printf("%s\n", buffer);
  }
    memset(buffer, 0, BUFFER_SIZE);

  // Send QUIT command
  send(sockfd, "QUIT\r\n", 6, 0);
  recv(sockfd, buffer, BUFFER_SIZE, 0); // Read QUIT response
  if (is_debug){
      printf("%s\n", buffer);
  }
    memset(buffer, 0, BUFFER_SIZE);

  close(sockfd);
  return 0;
}

// int main(int argc, char *argv[])
// {
//   // bool is_debug = true;
//   std::string content = "From: alice@localhost\nTo: jiening@seas.upenn.edu\nSubject: Test\n\nHello, this is a test email.\n";
//   send_external_mails(argv[1], argv[2], content);
// }
