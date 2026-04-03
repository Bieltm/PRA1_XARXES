#include "udp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

int udp_open(){
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0){
        perror("Error a la creació del socket");
        return -1;
    }
    return s;
}

int udp_send(int sockfd, char *data, int len_data, struct sockaddr *cap_a){
    int s = sendto(sockfd, data, len_data, 0, (struct sockaddr *)cap_a, sizeof(struct sockaddr));    
    if (s < 0){
        perror("Error al enviar un socket");
    }
    return s;
}

int udp_recv(int sockfd, char *data, int len_data, struct sockaddr *de){
    socklen_t addr_len = sizeof(struct sockaddr_in);
    int s = recvfrom(sockfd, data, len_data, 0, (struct sockaddr *)de, &addr_len);
    if (s < 0){
        perror("Error al rebre el paquet");
    }
    return s;
}