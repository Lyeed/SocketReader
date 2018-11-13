#include "dialog.h"

void textDialogClose(GtkWidget *widget) {
  GtkTextIter start, end;
  gtk_text_buffer_get_iter_at_offset(app->buffer, &start, 0);
  gtk_text_buffer_get_iter_at_offset(app->buffer, &end, gtk_text_buffer_get_char_count(app->buffer));
  app->filters = gtk_text_buffer_get_text(app->buffer, &start, &end, FALSE);
  g_print("dialog_close() filters=[%s]\n", app->filters);
  gtk_widget_destroy(widget);
}

void textDialogOpen(GtkWindow *parent) {
  GtkWidget *dialog = gtk_dialog_new_with_buttons("Filters",
                                       parent,
                                       GTK_DIALOG_DESTROY_WITH_PARENT,
                                       "OK",
                                       GTK_RESPONSE_NONE,
                                       NULL);
  GtkWidget *content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
  GtkWidget *label = gtk_text_view_new();
  app->buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(label));

  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(label), GTK_WRAP_NONE);
  gtk_text_view_set_accepts_tab(GTK_TEXT_VIEW(label), FALSE);
  gtk_text_buffer_set_text(app->buffer, app->filters, -1);
  g_signal_connect_swapped(dialog, "response", G_CALLBACK(textDialogClose), dialog);
  gtk_container_add(GTK_CONTAINER(content_area), label);
  gtk_widget_show_all(dialog);
}
