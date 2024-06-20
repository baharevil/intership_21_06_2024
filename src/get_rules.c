#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "firewall.h"
#include "runtime.h"

int get_rules(runtime_t *runtime) {
  if (!runtime || !runtime->filename) return EFAULT;

  int code = 0;
  rule_t temp = {0};

  FILE *file = NULL;
  file = fopen(runtime->filename, "rt");
  code = (file == NULL) * EBADF;

  char *buf = NULL, *action_buf = NULL, *ptr = NULL;

  if (!code) buf = malloc(BUFSIZ * sizeof(char));

  if (!code) action_buf = malloc(7 * sizeof(char));

  if (!code) code = (buf == NULL) * ENOMEM;

  while (!code && fscanf(file, "%[^\n]", buf) != EOF) {
    file->_IO_read_ptr += 1;
    // Пропускаем строки-комментарии и пустые строки
    if (buf[0] == '#' || buf[0] == 0) {
      continue;
    }

    // src
    ptr = strstr(buf, "src:");
    if (ptr) {
      code =
          sscanf(ptr, " src: %hhu.%hhu.%hhu.%hhu/%hhu", &temp.data.src.octet1,
                 &temp.data.src.octet2, &temp.data.src.octet3,
                 &temp.data.src.octet4, &temp.data.src.cidr);
    }
    // dst
    if (code != EOF && (ptr = strstr(buf, "dst:"))) {
      code = sscanf(ptr, "dst: %hhu.%hhu.%hhu.%hhu/%hhu", &temp.data.dst.octet1,
                    &temp.data.dst.octet2, &temp.data.dst.octet3,
                    &temp.data.dst.octet4, &temp.data.dst.cidr);
    }
    // proto
    if (code != EOF && (ptr = strstr(buf, "proto:"))) {
      char *proto_text = NULL;
      proto_text = malloc(BUFSIZ * sizeof(char));
      if (proto_text) {
        code = sscanf(ptr, "proto: %s", proto_text);
        temp.data.proto = protocols(proto_text);
        free(proto_text);
      }
    }
    // src_port
    if (code != EOF && (ptr = strstr(buf, "sport:"))) {
      code = sscanf(ptr, "sport: %hu", &temp.data.src_port);
    }
    // dst_port
    if (code != EOF && (ptr = strstr(buf, "dport:"))) {
      code = sscanf(ptr, "dport: %hu", &temp.data.dst_port);
    }
    // action
    if (code != EOF && (ptr = strstr(buf, "=>"))) {
      code = sscanf(ptr, "=> %6s", action_buf);
      if (strcmp(action_buf, "ACCEPT") == 0)
        temp.action = accept;
      else if (strcmp(action_buf, "DROP") == 0)
        temp.action = drop;
    }

    // errors handle
    if (code == EOF || !temp.action)
      code = ENOKEY;
    else {
      code = 0;
    }
    // limitations
    if (!code) {
      if (temp.data.src.full_addr &&
          (temp.data.src.cidr == 0 || temp.data.src.cidr > 32))
        temp.data.src.cidr = 32;
      if (temp.data.dst.full_addr &&
          (temp.data.dst.cidr == 0 || temp.data.dst.cidr > 32))
        temp.data.dst.cidr = 32;

      temp.id = ++runtime->rules_count;
      runtime->rules =
          realloc(runtime->rules, runtime->rules_count * sizeof(rule_t));
      if (runtime->rules) {
        memcpy(&runtime->rules[runtime->rules_count - 1], &temp,
               sizeof(rule_t));
      }
      // zeroing
      memset(&temp, 0, sizeof(rule_t));
      memset(buf, 0, BUFSIZ);
      memset(action_buf, 0, 7);
    }
  }

  if (file) fclose(file);
  if (buf) free(buf);
  if (action_buf) free(action_buf);
  return code;
}
