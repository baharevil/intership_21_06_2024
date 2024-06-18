#include <errno.h>
#include <stddef.h>
#include <getopt.h>

#include "runtime.h"

int get_runtime(runtime_t *runtime, int argc, char **argv) {
  int code = 0;
  const char *short_options = "f:h";
  const struct option long_options[] = {
      {"file", required_argument, NULL, 'f'},
      {"help", no_argument, NULL, '1'},
      {0, 0, 0, 0}};
  int c = 0;

  while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1 &&
         code == 0) {
    if (c == 'f')
      runtime->db_name = optarg;
    if (c == 'h')
      code = -1;
    if (c == '?')
      code = EINVAL;
  }

  if (!code)
    code = (c == -1 && !runtime->db_name) * EINVAL;

  return code;
}


