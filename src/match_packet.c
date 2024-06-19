#include <errno.h>
#include <stdint.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>

#include "firewall.h"
#include "runtime.h"

int match_packet(rule_t *rule, packet_t *packet) {
  if(!rule || !packet) return EINVAL;

  int code = 0,
  src_match = 0,
  dst_match = 0;
  
  ip_addr_t rule_src_net_mask = {0},
            // rule_src_net_wildmask = {0},
            rule_dst_net_mask = {0},
            // rule_dst_net_wildmask = {0},
            rule_src_net_addr = {0},
            rule_dst_net_addr = {0},
            packet_src_net_addr = {0},
            packet_dst_net_addr = {0};
  
  rule_src_net_mask.full_addr = 1;
  rule_dst_net_mask.full_addr = 1;

  for(uint32_t i = 0, j = rule->data.src.cidr; i < 32; i++, j -= (j > 0)) {
    rule_src_net_mask.full_addr <<= 1;
    rule_src_net_mask.full_addr += (j > 0);
  }
  rule_src_net_addr.full_addr = rule->data.src.full_addr & rule_src_net_mask.full_addr;
//   rule_src_net_wildmask.full_addr = ~rule_src_net_mask.full_addr;
  packet_src_net_addr.full_addr = packet->src.full_addr & rule_src_net_mask.full_addr;
  src_match = (packet_src_net_addr.full_addr == rule_src_net_addr.full_addr);

  for(uint32_t i = 0, j = rule->data.dst.cidr; i < 32; i++, j -= (j > 0)) {
    rule_dst_net_mask.full_addr <<= 1;
    rule_dst_net_mask.full_addr += (j > 0);
  }
  rule_dst_net_addr.full_addr = rule->data.dst.full_addr & rule_dst_net_mask.full_addr;
//   rule_dst_net_wildmask.full_addr = ~rule_dst_net_mask.full_addr;

  packet_dst_net_addr.full_addr = packet->dst.full_addr & rule_dst_net_mask.full_addr;
  dst_match = (packet_dst_net_addr.full_addr == rule_dst_net_addr.full_addr);


if (src_match && dst_match) code = 1;

//   sport_match = 0,
//   dport_match = 0;

  return code;
}