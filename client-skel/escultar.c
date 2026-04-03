#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "udp.h"

int main() {
    int fd = udp_open();
    struct sockaddr_in local, remota;
    char buffer[1024];

    local.sin_family = AF_INET;
    local.sin_port = htons(5000); // Port on escoltem
    local.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        perror("Error bind"); return 1;
    }

    printf("Esperant dades al port 5000...\n");
    int n = udp_recv(fd, buffer, sizeof(buffer), (struct sockaddr *)&remota);
    
    if (n > 0) {
        printf("Rebut de %s: %s\n", inet_ntoa(remota.sin_addr), buffer);
    }

    close(fd);
    return 0;
}