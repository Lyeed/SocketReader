#include "dialog.h"
#include "sniffer.h"

void textDialogClose(GtkWidget *widget) {
  GtkTextIter start, end;
  gtk_text_buffer_get_iter_at_offset(app->buffer, &start, 0);
  gtk_text_buffer_get_iter_at_offset(app->buffer, &end, gtk_text_buffer_get_char_count(app->buffer));
  app->filters = gtk_text_buffer_get_text(app->buffer, &start, &end, FALSE);
  g_print("dialog_close() filters=[%s]\n", app->filters);
  gtk_widget_destroy(widget);
}

void textDialogOpen(GtkWindow *parent) {
  g_print("textDialogOpen()\n");
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

void packetDialogOpen(const raw_packet_t *packet) {
  g_print("packetDialogOpen()\n");
  char title[1024];
  sprintf(title, "Packet %d info", packet->num);
  GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  GtkWidget *info = gtk_text_view_new(),
            *hexa = gtk_text_view_new(),
            *ascii = gtk_text_view_new();
  GtkTextBuffer *infoBuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(info)),
                 *hexaBuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(hexa)),
                 *asciiBuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ascii));
  GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);

  gtk_window_set_default_size(GTK_WINDOW(window), 512, 512);

  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(hexa), GTK_WRAP_CHAR);
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ascii), GTK_WRAP_CHAR);
  gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ascii), GTK_WRAP_WORD);

  gtk_text_buffer_set_text(infoBuffer, getBigDetails(packet), -1);
  gtk_text_buffer_set_text(hexaBuffer, getHexa(packet), -1);
  gtk_text_buffer_set_text(asciiBuffer, getAscii(packet), -1);

  gtk_text_view_set_editable(GTK_TEXT_VIEW(info), FALSE);
  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(info), FALSE);
  gtk_text_view_set_editable(GTK_TEXT_VIEW(hexa), FALSE);
  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(hexa), FALSE);
  gtk_text_view_set_editable(GTK_TEXT_VIEW(ascii), FALSE);
  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(ascii), FALSE);

  gtk_box_pack_start(GTK_BOX(box), info, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(box), hexa, TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(box), ascii, TRUE, TRUE, 0);
  gtk_container_add(GTK_CONTAINER(window), box);

  gtk_widget_show_all(window);
}
