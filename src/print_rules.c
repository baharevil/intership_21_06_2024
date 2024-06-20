#include <errno.h>
#include <stdio.h>

#include "firewall.h"
#include "runtime.h"

int print_rules(runtime_t *runtime) {
  if (!runtime || !runtime->filename) return EINVAL;

  int code = 0;

  for(uint16_t i = 0; i < runtime->rules_count; i++) {
      printf("id: %-3hu ", runtime->rules[i].id);
      printf("src: %hhu.%hhu.%hhu.%hhu",
      runtime->rules[i].data.src.octet1,
      runtime->rules[i].data.src.octet2,
      runtime->rules[i].data.src.octet3,
      runtime->rules[i].data.src.octet4);
      printf("/%hhu", runtime->rules[i].data.src.cidr);
      printf(":%hu\t", runtime->rules[i].data.src_port);
      printf("dst: %hhu.%hhu.%hhu.%hhu",
      runtime->rules[i].data.dst.octet1,
      runtime->rules[i].data.dst.octet2,
      runtime->rules[i].data.dst.octet3,
      runtime->rules[i].data.dst.octet4);
      printf("/%hhu", runtime->rules[i].data.dst.cidr);
      printf(":%hu\t", runtime->rules[i].data.dst_port);
      printf("proto: %hhu ", runtime->rules[i].data.proto);
      printf("action: %s\n", (runtime->rules[i].action == 1) ? "ACCEPT" : "DROP");
  }
  return code;
}