#include "protocol.h"
#include <arpa/inet.h>

int encode(uint8_t *output, uint8_t opcode, uint16_t client_id, uint8_t payload[8], uint8_t *eth_frame, int eth_len){
    output[0] = opcode;
    uint16_t cid_net = htons(client_id);
    memcpy(&output[1], &cid_net, 2);
    if (payload != NULL){
        memcpy(&output[3], payload, 8);
    } else {
        memset(&output[3], 0, 8);
    }
    if (opcode == 0x03 && eth_frame != NULL) {
        memcpy(&output[11], eth_frame, eth_len);
        return 11 + eth_len;
    }
    return 11;
}

int descode(uint8_t *input, int input_len, uint8_t *opcode, uint16_t *client_id, uint8_t *payload, uint8_t *eth_frame) {
    if (input_len < 11) {
        return -1;
    }
    *opcode = input[0];
    uint16_t cid_net;
    memcpy(&cid_net, &input[1], 2);
    *client_id = ntohs(cid_net);
    memcpy(payload, &input[3], 8);
    int eth_len = 0;
    if (*opcode == 0x03 && input_len > 11) {
        eth_len = input_len - 11;
        memcpy(eth_frame, &input[11], eth_len);
    }
    return eth_len;
}