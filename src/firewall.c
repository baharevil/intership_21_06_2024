#include <errno.h>
#include <stdio.h>

#include "firewall.h"
#include "runtime.h"
#include "packet.h"

/**
 * @brief Основной цикл программы псевдо-файрвола
*/
int main (int argc, char *argv[]) {
  int code = 0;
  runtime_t runtime = {0};

  code = (argc == 1) * EINVAL;

  if (!code)
    code = get_runtime(&runtime, argc, argv);


  if (!code) {
    // TODO: Run here
    printf("%s\n", runtime.db_name);
  }

  if (code) {
    help();
    code += (code < 0);
  }

  return code;
}
