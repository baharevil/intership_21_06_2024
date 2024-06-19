#ifndef FIREWALL_H
#define FIREWALL_H

#include "runtime.h"

int get_runtime(runtime_t *runtime, int argc, char **argv);
int get_rules(runtime_t *runtime);
int print_rules(runtime_t *runtime);
int process_packets(runtime_t *runtime);
int get_packet(packet_t *packet, char *string);
int match_packet(rule_t *rule, packet_t *packet);
void help();

#endif