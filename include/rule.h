#ifndef RULE_H
#define RULE_H

#include <stdint.h>
#include "packet.h"

typedef enum {
  none = 0,
  accept,
  drop
} action_t;

typedef struct {
  uint16_t id;
  struct ip_proto data;
  action_t action;
} rule_t;

#endif