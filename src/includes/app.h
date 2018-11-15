#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <gtk/gtk.h>
#include <time.h>
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
  guint packetsCount;
  GtkWidget *window;
  GtkWidget *text;
  GtkListStore *store;
  GtkTreeIter iter;
  GtkTextBuffer *buffer;
  time_t start;
  char *filters;
  int run;
  buttons_t *buttons;
} app_t;

app_t *app;

void appOpen(void);
void *appDestroy(void);

#endif /* APP_H_ */
