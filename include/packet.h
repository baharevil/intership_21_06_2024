#ifndef PACKET_H
#define PACKET_H

#include <endian.h>
#include <stdint.h>

typedef struct {
  union {
    uint32_t full_addr;
    struct {
    #if __BYTE_ORDER == __BIG_ENDIAN
    uint8_t octet1;
    uint8_t octet2;
    uint8_t octet3;
    uint8_t octet4;
    #endif /* Big endian.  */
    #if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t octet4;
    uint8_t octet3;
    uint8_t octet2;
    uint8_t octet1;
    #endif /* Little endian.  */
    };
  };
  uint8_t cidr;
} ip_addr_t;

struct ip_proto {
  ip_addr_t src;
  ip_addr_t dst;
  uint16_t  src_port;
  uint16_t  dst_port;
  uint8_t   proto;
};

typedef struct ip_proto packet_t;

#endif