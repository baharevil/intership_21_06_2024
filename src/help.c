#include <stdio.h>

void help() {
  printf(
      "\
Usage: firewall -f [FW RULES FILE]...\n\
Processing firewall rules from stdin.\n\
Example: cat traffic_dump.txt | firewall -f rules1.fw\n"
  );
}