#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#define VPN_HEADER_SIZE 11
typedef struct {
    uint8_t opcode;
    uint16_t client_id;
    uint8_t payload[8];
} vpn_header_t;

int encode(uint8_t *output, uint8_t opcode, uint16_t client_id, uint8_t payload[8], uint8_t *eth_frame, int eth_len);

int descode(uint8_t *input, int input_len, uint8_t *opcode, uint16_t *client_id, uint8_t *payload, uint8_t *eth_frame);