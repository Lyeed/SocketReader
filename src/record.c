#include "record.h"
#include "sniffer.h"
#include "app.h"

void *timer_start(void *data) {
  (void)data;
  app->timer = 0;
  g_print("timer_start() thread\n");
  while (app->run) {
    app->timer += 0.0001;
    usleep(1);
  }
  g_print("timer_start() exited\n");
  return NULL;
}

void record_start(GtkWidget *widget, gpointer data) {
  pthread_t sniffer_thread, timer_thread;

  g_print("record_start()\n");
  app->run = 1;
  gtk_list_store_clear(app->store);
  gtk_widget_set_sensitive(widget, FALSE);
  gtk_widget_set_sensitive(app->buttons->buttonStop, TRUE);
  pthread_create(&sniffer_thread, NULL, sniffer, NULL);
  pthread_create(&timer_thread, NULL, timer_start, NULL);
  (void)data;
}

void record_stop(GtkWidget *widget, gpointer data) {
  g_print("record_stop()\n");
  gtk_widget_set_sensitive(widget, FALSE);
  gtk_widget_set_sensitive(app->buttons->buttonStart, TRUE);
  app->run = 0;
  (void)data;
}

void record_export(GtkWidget *widget, gpointer data) {
  g_print("record_export()\n");
  (void)data;
  (void)widget;
}

void record_import(GtkWidget *widget, gpointer data) {
  g_print("record_import()\n");
  (void)data;
  (void)widget;
}
