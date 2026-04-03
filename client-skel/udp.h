#include <netdb.h>

int udp_open();
int udp_send(int sockfd, char *data, int len_data, struct sockaddr *cap_a);
int udp_recv(int sockfd, char *data, int len_data, struct sockaddr *de);