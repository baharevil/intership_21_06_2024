#include <errno.h>
#include <getopt.h>
#include <stddef.h>

#include "runtime.h"

int get_runtime(runtime_t *runtime, int argc, char **argv) {
  int code = 0;
  const char *short_options = "f:ph";
  const struct option long_options[] = {{"file", required_argument, NULL, 'f'},
                                        {"print", no_argument, NULL, 'p'},
                                        {"help", no_argument, NULL, 'h'},
                                        {0, 0, 0, 0}};
  int c = 0;

  while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) !=
             -1 &&
         code == 0) {
    if (c == 'f') runtime->filename = optarg;
    if (c == 'p') runtime->print = 1;
    if (c == 'h') runtime->help = 1;
    if (c == '?') code = EINVAL;
  }

  if (!code) code = (c == -1 && !runtime->filename) * EINVAL;

  return code;
}
