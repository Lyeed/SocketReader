#include "app.h"

int main(int ac, char **av) {
  app = malloc(sizeof(app_t));
  import_pcapfile(av[1]);
  export_pcapfile(av[2]);
  //appOpen();
  return 0;
}
