#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>

#include "tap.h"
#include "protocol.h"
#include "udp.h"

#define KEEPALIVE_INTERVAL_SEC 10
#define MAX_FRAME_SIZE         65535

typedef struct {
    const char *tap_if;
    const char *server_ip;
    int         port;
    int         client_id;
    char        password[9]; 
} vpn_config_t;

void client_run(vpn_config_t *cfg, int tap_fd);

static void print_usage(const char *prog) {
    fprintf(stderr, "Uso: %s --tap <if> --server <ip> --port <port> --id <id> --password <pw>\n", prog);
}

static int validate_password(const char *pw) {
    if (strlen(pw) != 8) return -1;
    for (int i = 0; i < 8; i++) {
        if (!isalnum((unsigned char)pw[i])) return -1;
    }
    return 0;
}

static int parse_args(int argc, char *argv[], vpn_config_t *cfg) {
    int has_tap = 0, has_server = 0, has_port = 0, has_id = 0, has_password = 0;
    memset(cfg, 0, sizeof(*cfg));

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return -1;
        } else if (strcmp(argv[i], "--tap") == 0 && i + 1 < argc) {
            cfg->tap_if = argv[++i];
            has_tap = 1;
        } else if (strcmp(argv[i], "--server") == 0 && i + 1 < argc) {
            cfg->server_ip = argv[++i];
            has_server = 1;
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            cfg->port = atoi(argv[++i]);
            has_port = 1;
        } else if (strcmp(argv[i], "--id") == 0 && i + 1 < argc) {
            cfg->client_id = atoi(argv[++i]);
            has_id = 1;
        } else if (strcmp(argv[i], "--password") == 0 && i + 1 < argc) {
            const char *pw = argv[++i];
            if (validate_password(pw) == 0) {
                memcpy(cfg->password, pw, 8);
                cfg->password[8] = '\0';
                has_password = 1;
            }
        }
    }
    if (has_tap && has_server && has_port && has_id && has_password) return 1;
    return 0; 
}
void client_run(vpn_config_t *cfg, int tap_fd) {
    int udp_fd = udp_open();
    if (udp_fd < 0) {
        perror("Error al abrir socket UDP");
        return;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(cfg->port);
    inet_pton(AF_INET, cfg->server_ip, &server_addr.sin_addr);

    uint8_t buffer_in[MAX_FRAME_SIZE + 20];
    uint8_t eth_frame[MAX_FRAME_SIZE];
    uint8_t paquet_out[MAX_FRAME_SIZE + 20];

    // estat_connexio: 0 = No registrat, 1 = Esperant validació contrasenya, 2 = Autenticat
    int estat_connexio = 0; 
    time_t ultim_enviament = 0; 

    printf("Client %d iniciat. Intentant conectar...\n", cfg->client_id);

    while (1) {
        fd_set descriptors;
        FD_ZERO(&descriptors);
        FD_SET(udp_fd, &descriptors);
        FD_SET(tap_fd, &descriptors);

        int max_fd = (udp_fd > tap_fd) ? udp_fd : tap_fd;
        struct timeval tv = {1, 0};

        if (select(max_fd + 1, &descriptors, NULL, NULL, &tv) > 0) {
            
            if (FD_ISSET(udp_fd, &descriptors)) {
                struct sockaddr_in from;
                int n = udp_recv(udp_fd, (char *)buffer_in, sizeof(buffer_in), (struct sockaddr *)&from);
                if (n > 0) {
                    uint8_t op, pay[8];
                    uint16_t id;
                    int eth_len = descode(buffer_in, n, &op, &id, pay, eth_frame);

                    if (op == 0x05) {
                        if (estat_connexio == 0) {
                            printf("El servidor accepta el REGISTER! Enviant contrasenya (AUTH)...\n");
                            encode(paquet_out, 0x02, cfg->client_id, (uint8_t*)cfg->password, NULL, 0);
                            udp_send(udp_fd, (char *)paquet_out, 11, (struct sockaddr *)&server_addr);
                            estat_connexio = 1;
                            ultim_enviament = time(NULL);
                        } 
                        else if (estat_connexio == 1) {
                            printf("Autenticació completada amb exit!\n");
                            estat_connexio = 2;
                        }
                    } 
                    else if (op == 0x06) { 
                        printf("El servidor ha rebutjat la connexio! (Revisa credencials)\n");
                        estat_connexio = 0;
                    }
                    else if (op == 0x03) {
                        if (estat_connexio == 2 && eth_len > 0) {
                            write(tap_fd, eth_frame, eth_len);
                        }
                    }
                }
            }

            if (FD_ISSET(tap_fd, &descriptors)) {
                int n = read(tap_fd, eth_frame, sizeof(eth_frame));
                if (n > 0 && estat_connexio == 2) { 
                    int len = encode(paquet_out, 0x03, cfg->client_id, NULL, eth_frame, n);
                    udp_send(udp_fd, (char *)paquet_out, len, (struct sockaddr *)&server_addr);
                    ultim_enviament = time(NULL);
                }
            }
        }

        time_t ahora = time(NULL);
        
        if (estat_connexio == 0) {
            if (ahora - ultim_enviament >= 3) {
                printf("Enviant REGISTER al servidor...\n");
                encode(paquet_out, 0x01, cfg->client_id, NULL, NULL, 0);
                udp_send(udp_fd, (char *)paquet_out, 11, (struct sockaddr *)&server_addr);
                ultim_enviament = ahora;
            }
        } 
        else if (estat_connexio == 1) {
            if (ahora - ultim_enviament >= 3) {
                printf("Reintentant enviar contrasenya (AUTH)...\n");
                encode(paquet_out, 0x02, cfg->client_id, (uint8_t*)cfg->password, NULL, 0);
                udp_send(udp_fd, (char *)paquet_out, 11, (struct sockaddr *)&server_addr);
                ultim_enviament = ahora;
            }
        } 
        else if (estat_connexio == 2) {
            if (ahora - ultim_enviament >= KEEPALIVE_INTERVAL_SEC) {
                encode(paquet_out, 0x04, cfg->client_id, NULL, NULL, 0);
                udp_send(udp_fd, (char *)paquet_out, 11, (struct sockaddr *)&server_addr);
                ultim_enviament = ahora;
            }
        }
    }
}

int main(int argc, char *argv[]) {
    vpn_config_t cfg;
    int res = parse_args(argc, argv, &cfg);
    if (res == 1) { 
        int tap_fd = tap_open(cfg.tap_if);
        if (tap_fd < 0) {
            perror("Error obrint el TAP");
            return 1;
        }
        client_run(&cfg, tap_fd);
        close(tap_fd);
        return 0;
    } 
    return (res < 0) ? 0 : 1;
}