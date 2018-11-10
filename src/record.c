#include "record.h"
#include "sniffer.h"
#include "app.h"

void *timer_start(void *data) {
  g_print("timer_start() thread\n");
  (void)data;
  app->timer = 0;
  while (app->run) {
    app->timer += 0.0001;
    usleep(1);
  }
  g_print("timer_start() exited\n");
  return NULL;
}

void record_start(GtkWidget *widget, gpointer data) {
  g_print("record_start()\n");
  pthread_t sniffer_thread, timer_thread;

  app->run = 1;
  gtk_list_store_clear(app->store);
  gtk_widget_set_sensitive(widget, FALSE);
  gtk_widget_set_sensitive(app->buttons->buttonImport, FALSE);
  gtk_widget_set_sensitive(app->buttons->buttonStop, TRUE);
  gtk_widget_set_sensitive(app->buttons->buttonExport, TRUE);
  pthread_create(&sniffer_thread, NULL, sniffer, NULL);
  pthread_create(&timer_thread, NULL, timer_start, NULL);
  (void)data;
}

void record_stop(GtkWidget *widget, gpointer data) {
  g_print("record_stop()\n");
  gtk_widget_set_sensitive(widget, FALSE);
  gtk_widget_set_sensitive(app->buttons->buttonStart, TRUE);
  gtk_widget_set_sensitive(app->buttons->buttonImport, TRUE);
  gtk_widget_set_sensitive(app->buttons->buttonExport, FALSE);
  app->run = 0;
  (void)data;
}

void record_export(GtkWidget *widget, gpointer data) {
  g_print("record_export()\n");
  GtkWidget *dialog = gtk_file_chooser_dialog_new("Save File",
                                      GTK_WINDOW(app->window),
                                      GTK_FILE_CHOOSER_ACTION_SAVE,
                                      "Cancel",
                                      GTK_RESPONSE_CANCEL,
                                      "Save",
                                      GTK_RESPONSE_ACCEPT,
                                      NULL);
  if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
    GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
    char *filename = gtk_file_chooser_get_filename(chooser);
    export_pcapfile(filename);
    g_free(filename);
  }
  gtk_widget_destroy(dialog);
  (void)data;
  (void)widget;
}

void record_import(GtkWidget *widget, gpointer data) {
  g_print("record_import()\n");
  gtk_widget_set_sensitive(widget, FALSE);
  GtkWidget *dialog = gtk_file_chooser_dialog_new("Open File",
                                      GTK_WINDOW(app->window),
                                      GTK_FILE_CHOOSER_ACTION_OPEN,
                                      "Cancel",
                                      GTK_RESPONSE_CANCEL,
                                      "Open",
                                      GTK_RESPONSE_ACCEPT,
                                      NULL);
  if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
    GtkFileChooser *chooser = GTK_FILE_CHOOSER(dialog);
    char *filename = gtk_file_chooser_get_filename(chooser);
    import_pcapfile(filename);
    g_free(filename);
  }
  gtk_widget_destroy(dialog);
  (void)data;
}
