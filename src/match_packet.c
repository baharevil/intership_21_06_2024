#include <errno.h>
#include <stdint.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>

#include "firewall.h"
#include "runtime.h"

static uint32_t cidr_to_netmask(uint32_t cidr);

int match_packet(rule_t *rule, packet_t *packet) {
  if(!rule || !packet) return EINVAL;

  int code = 0,
  src_match = 0,
  dst_match = 0,
  sport_match = 0,
  dport_match = 0,
  proto_match = 0;
  
  ip_addr_t rule_src_net_mask = {0},
            rule_dst_net_mask = {0},
            rule_src_net_addr = {0},
            rule_dst_net_addr = {0},
            packet_src_net_addr = {0},
            packet_dst_net_addr = {0};
  
  rule_src_net_mask.full_addr = cidr_to_netmask(rule->data.src.cidr);
  rule_src_net_addr.full_addr = rule->data.src.full_addr & rule_src_net_mask.full_addr;
  packet_src_net_addr.full_addr = packet->src.full_addr & rule_src_net_mask.full_addr;
  src_match = (packet_src_net_addr.full_addr == rule_src_net_addr.full_addr);

  rule_dst_net_mask.full_addr = cidr_to_netmask(rule->data.dst.cidr);
  rule_dst_net_addr.full_addr = rule->data.dst.full_addr & rule_dst_net_mask.full_addr;
  packet_dst_net_addr.full_addr = packet->dst.full_addr & rule_dst_net_mask.full_addr;
  dst_match = (packet_dst_net_addr.full_addr == rule_dst_net_addr.full_addr);

  if (rule->data.src_port)
    sport_match = (rule->data.src_port == packet->src_port);
  else
    sport_match = 1;

  if (rule->data.dst_port)
    dport_match = (rule->data.dst_port == packet->dst_port);
  else
    dport_match = 1;

  if (rule->data.proto)
    proto_match = (rule->data.proto == packet->proto);
  else
    proto_match = 1;

  if (src_match && dst_match && sport_match && dport_match && proto_match) code = 1;

  return code;
}

static uint32_t cidr_to_netmask(uint32_t cidr) {
  uint32_t netmask = 0;

  for(uint32_t i = 0, j = cidr; cidr > 0 && i < 32; i++, j -= (j > 0)) {
    netmask += (j > 0);
    netmask <<= 1;
  }

  return netmask;
}