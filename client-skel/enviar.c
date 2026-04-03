#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "udp.h"

int main() {
    int fd = udp_open();
    struct sockaddr_in desti;
    char *msg = "Missatge entre terminals!";

    desti.sin_family = AF_INET;
    desti.sin_port = htons(5000);
    desti.sin_addr.s_addr = inet_addr("127.0.0.1");

    printf("Enviant dades...\n");
    udp_send(fd, msg, strlen(msg) + 1, (struct sockaddr *)&desti);

    close(fd);
    return 0;
}