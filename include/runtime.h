#ifndef RUNTIME_H
#define RUNTIME_H

#include <stdint.h>

#include "rule.h"

typedef struct {
  char *filename;
  rule_t *rules;
  uint16_t rules_count;
  uint8_t help : 1;
  uint8_t print : 1;
} runtime_t;

#endif