#include <errno.h>
#include <stdint.h>
#include <malloc.h>
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
  
  char *buf = NULL;
  if (!code)
    buf = malloc(BUFSIZ * sizeof(char));
  
  char *action_buf = NULL;
  if (!code)
    action_buf = malloc(7 * sizeof(char));

  if (!code)
    code = (buf == NULL) * ENOMEM;

  while(!code && fscanf(file, "%[^\n]", buf) != EOF) {
    file->_IO_read_ptr += 1;
    // Пропускаем строки-комментарии и пустые строки
    if(buf[0] == '#' || buf[0] == 0) {
      continue;
    }
    // Парсим данные
    code = sscanf(buf, "%hhu.%hhu.%hhu.%hhu/%hhu:%hu %hhu.%hhu.%hhu.%hhu/%hhu:%hu %hhu %s",
        &temp.data.src.octet1,
        &temp.data.src.octet2,
        &temp.data.src.octet3,
        &temp.data.src.octet4,
        &temp.data.src.cidr,
        &temp.data.src_port,

        &temp.data.dst.octet1,
        &temp.data.dst.octet2,
        &temp.data.dst.octet3,
        &temp.data.dst.octet4,
        &temp.data.dst.cidr,
        &temp.data.dst_port,

        &temp.data.proto,
        action_buf);

    if (code == EOF || code != 14)
      code = ENOKEY;
    else {
      code = 0;
    }

    if (!code) {
      if(strcmp(action_buf, "ACCEPT") == 0)
        temp.action = accept;
      else
        temp.action = drop;

      if (temp.data.src.cidr > 32)
        temp.data.src.cidr = 32;

      if (temp.data.dst.cidr > 32)
        temp.data.dst.cidr = 32;

      temp.id = ++runtime->rules_count;

      runtime->rules = realloc(runtime->rules, runtime->rules_count * sizeof(rule_t));
      if (runtime->rules) {
        memcpy(&runtime->rules[runtime->rules_count - 1], &temp, sizeof(rule_t));
      }
      memset(&temp, 0, sizeof(rule_t));
      memset(buf, 0, BUFSIZ);
      memset(action_buf, 0, 7);
    }
  }

  if(file) fclose(file);
  if(buf) free(buf);
  if(action_buf) free(action_buf);
  return code;
}
