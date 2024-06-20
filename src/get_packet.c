#include <errno.h>
#include <stdio.h>

#include "firewall.h"
#include "runtime.h"

int get_packet(packet_t *packet, char *string) {
  if (!packet || !string) return EINVAL;
  int code = 0;

  code = sscanf(string, "%hhu.%hhu.%hhu.%hhu %hhu.%hhu.%hhu.%hhu %hu %hu %hhu",
                &packet->src.octet1, &packet->src.octet2, &packet->src.octet3,
                &packet->src.octet4, &packet->dst.octet1, &packet->dst.octet2,
                &packet->dst.octet3, &packet->dst.octet4, &packet->src_port,
                &packet->dst_port, &packet->proto);

  if (code == 11)
    code = 0;
  else
    code = EPROTO;

  return code;
}
