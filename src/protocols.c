/**!
 *  @brief Based on IANA Assigned Internet Protocol Numbers
 * (https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
 */
#include <string.h>

int protocols(char *string) {
  int proto = 0;

  if (strcmp(string, "icmp") == 0)
    proto = 1;
  else if (strcmp(string, "igmp") == 0)
    proto = 2;
  else if (strcmp(string, "ggp") == 0)
    proto = 3;
  else if (strcmp(string, "ipv4") == 0)
    proto = 4;
  else if (strcmp(string, "st") == 0)
    proto = 5;
  else if (strcmp(string, "tcp") == 0)
    proto = 6;
  else if (strcmp(string, "cbt") == 0)
    proto = 7;
  else if (strcmp(string, "egp") == 0)
    proto = 8;
  else if (strcmp(string, "igp") == 0)
    proto = 9;
  else if (strcmp(string, "bbn-rcc-mon") == 0)
    proto = 10;
  else if (strcmp(string, "nvp") == 0)
    proto = 11;
  else if (strcmp(string, "pup") == 0)
    proto = 12;
  else if (strcmp(string, "argus") == 0)
    proto = 13;
  else if (strcmp(string, "emcon") == 0)
    proto = 14;
  else if (strcmp(string, "xnet") == 0)
    proto = 15;
  else if (strcmp(string, "chaos") == 0)
    proto = 16;
  else if (strcmp(string, "udp") == 0)
    proto = 17;
  // Can be continued...

  return proto;
}