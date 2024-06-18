#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

typedef union {
  uint32_t full_addr;
  struct {
    uint8_t octet1;
    uint8_t octet2;
    uint8_t octet3;
    uint8_t octet4;
  };
} ip_addr;

typedef struct {
  ip_addr   src;
  ip_addr   dst;
  uint16_t  src_port;
  uint16_t  dst_port;
  uint8_t   proto;
} packet_t;

#endif