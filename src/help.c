#include <stdio.h>

void help() {
  printf(
      "\
Processing stdin with firewall rules .\n\
Usage: firewall [key] [fw_rules_file]...\n\
keys options:\n\
-f, --file  - FW rules file name\n\
-p, --print - print FW rules from rules file before processing\n\
-h, --help  - this help\n\
Example: cat traffic_dump.txt | firewall -f rules1.fw\n"
  );
}