#include "firewall.h"

#include <errno.h>
#include <malloc.h>
#include <stdio.h>

#include "packet.h"
#include "runtime.h"

/**
 * @brief Основной цикл программы псевдо-файрвола
 */
int main(int argc, char *argv[]) {
  int code = 0;
  runtime_t runtime = {0};

  code = (argc == 1) * EINVAL;

  if (!code) code = get_runtime(&runtime, argc, argv);

  if (!code) {
    code = get_rules(&runtime);
  }

  if (!code && runtime.print) {
    print_rules(&runtime);
  }

  if (!code) {
    process_packets(&runtime);
  }

  // Блок обработки ошибок
  if (code == EINVAL || runtime.help) {
    help();
  } else if (code == EBADF) {
    fprintf(stderr, "Error opening file: %s\n", runtime.filename);
  } else if (code == ENOKEY) {
    fprintf(stderr, "Error reading rules from file: %s\nBad data\n",
            runtime.filename);
  } else if (code == EPROTO) {
    fprintf(stderr, "Error processing packets from stdin: %s\nBad data\n",
            runtime.filename);
  }

  if (runtime.rules) free(runtime.rules);
  return code;
}
