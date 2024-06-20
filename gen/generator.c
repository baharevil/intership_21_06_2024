#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
  int code = 0;

  code = (argc < 2) * EINVAL;

  if (!code) {
    int packet_count = 0;
    sscanf(argv[1], "%u", &packet_count);
    printf("source:\t\t\t destination:\t\t sport:  dport:  proto:\n");
    while (packet_count--) {
      printf(
          "%hhu.%hhu.%hhu.%-12hhu %hhu.%hhu.%hhu.%hhu\t\t %hu   %hu   %hhu\n",
          1 + rand() % 254, 1 + rand() % 254, 1 + rand() % 254,
          1 + rand() % 254, 1 + rand() % 254, 1 + rand() % 254,
          1 + rand() % 254, 1 + rand() % 254, 1 + rand() % 65535,
          1 + rand() % 65535, 1 + rand() % 17);
    }
  } else
    printf(
        "Random pseudo-packet generator\n\
Usage: generator [packet number]\n");

  return code;
}