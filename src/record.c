#include "record.h"
#include "sniffer.h"

void record_start(GtkWidget *widget, gpointer data) {
  raw_packet_t **raw = data;
  pthread_t thread;

  g_print("record_start()\n");
  gtk_widget_set_sensitive(widget, FALSE);
  pthread_create(&thread, NULL, sniffer, raw);
}

void record_stop(GtkWidget *widget, gpointer data) {
  g_print("record_stop()\n");
  gtk_widget_set_sensitive(widget, FALSE);
  (void)data;
}

void record_export(GtkWidget *widget, gpointer data) {
  raw_packet_t **raw = data;

  g_print("record_export()\n");
  (void)raw;
  (void)widget;
}

void record_import(GtkWidget *widget, gpointer data) {
  raw_packet_t **raw = data;

  g_print("record_import()\n");
  (void)raw;
  (void)widget;
}
