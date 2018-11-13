#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <gtk/gtk.h>
#include "sniffer.h"

#ifndef APP_H_
#define APP_H_

typedef struct buttons {
  GtkWidget *buttonStart;
  GtkWidget *buttonStop;
  GtkWidget *buttonImport;
  GtkWidget *buttonExport;
  GtkWidget *buttonFilters;
} buttons_t;

typedef struct app {
  raw_packet_t *raw;
  GtkWidget *window;
  GtkWidget *text;
  GtkListStore *store;
  GtkTreeIter iter;
  GtkTextBuffer *buffer;
  char *filters;
  int run;
  double timer;
  buttons_t *buttons;
} app_t;

app_t *app;

void appOpen(void);
void *appDestroy(void);

#endif /* APP_H_ */
