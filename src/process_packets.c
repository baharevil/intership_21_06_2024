#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "firewall.h"
#include "runtime.h"

int process_packets(runtime_t *runtime) {
  if (!runtime || !runtime->rules) return EINVAL;

  int code = 0;

  char *buf = NULL;
  packet_t *packet = NULL;
  uint16_t matched = 0;

  buf = malloc(BUFSIZ * sizeof(char));
  code = (buf == NULL) * ENOMEM;

  if (!code) {
    packet = malloc(sizeof(packet_t));
    code = (packet == NULL);
  }

  while (!code && scanf("%[^\n]", buf) != EOF) {
    stdin->_IO_read_ptr++;
    // Пропускаем строки-комментарии и пустые строки
    if (buf[0] == '#' || buf[0] == 0) {
      continue;
    }
    matched = 0;
    get_packet(packet, buf);
    printf(
        "%hhu.%hhu.%hhu.%hhu     \t %hhu.%hhu.%hhu.%-3hhu     \t %-10hu %-10hu "
        "%-2hhu",
        packet->src.octet1, packet->src.octet2, packet->src.octet3,
        packet->src.octet4, packet->dst.octet1, packet->dst.octet2,
        packet->dst.octet3, packet->dst.octet4, packet->src_port,
        packet->dst_port, packet->proto);

    for (uint16_t i = 0; !matched && i < runtime->rules_count; i++) {
      if (match_packet(&runtime->rules[i], packet))
        matched = runtime->rules[i].id;
    }

    if (matched)
      printf("   -   %-8s by id: %hu\n",
             (runtime->rules[matched - 1].action == 1) ? "ACCEPTED" : "DROPPED",
             matched);
    else
      printf("   -   DROPPED  by POLICY DROP\n");

    memset(buf, 0, BUFSIZ);
    memset(packet, 0, sizeof(packet_t));
  };

  if (buf) free(buf);
  if (packet) free(packet);
  return code;
}