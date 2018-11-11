#include "views.h"
#include "record.h"
#include "app.h"

void fill_list(const raw_packet_t *packet) {
  printf("A\n");
  gtk_list_store_append(app->store, &app->iter);
  printf("B\n");
  gtk_list_store_set(app->store, &app->iter,
                                    COLUMN_NUMBER, packet->num,
                                    COLUMN_TIME, packet->time,
                                    COLUMN_SOURCE, packet->ip->src_ip,
                                    COLUMN_DEST, packet->ip->dest_ip,
                                    COLUMN_PROTOCOL, getProtocol(packet->proto),
                                    COLUMN_LENGTH, packet->length,
                                    COLUMN_INFO, "Packet info",
                                    -1);
  printf("C\n");
}

static void add_columns(GtkTreeView *treeview) {
  GtkCellRenderer *renderer;
  GtkTreeViewColumn *column;

  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("No.", renderer, "text", COLUMN_NUMBER, NULL);
  gtk_tree_view_column_set_sort_column_id(column, COLUMN_NUMBER);
  gtk_tree_view_append_column(treeview, column);

  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Time", renderer, "text", COLUMN_TIME, NULL);
  gtk_tree_view_column_set_sort_column_id(column, COLUMN_TIME);
  gtk_tree_view_append_column(treeview, column);

  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Source", renderer, "text", COLUMN_SOURCE, NULL);
  gtk_tree_view_column_set_sort_column_id(column, COLUMN_SOURCE);
  gtk_tree_view_append_column(treeview, column);

  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Destination", renderer, "text", COLUMN_DEST, NULL);
  gtk_tree_view_column_set_sort_column_id(column, COLUMN_DEST);
  gtk_tree_view_append_column(treeview, column);

  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Protocol", renderer, "text", COLUMN_PROTOCOL, NULL);
  gtk_tree_view_column_set_sort_column_id(column, COLUMN_PROTOCOL);
  gtk_tree_view_append_column(treeview, column);

  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Length", renderer, "text", COLUMN_LENGTH, NULL);
  gtk_tree_view_column_set_sort_column_id(column, COLUMN_LENGTH);
  gtk_tree_view_append_column(treeview, column);

  renderer = gtk_cell_renderer_text_new();
  column = gtk_tree_view_column_new_with_attributes("Info", renderer, "text", COLUMN_INFO, NULL);
  gtk_tree_view_column_set_sort_column_id(column, COLUMN_INFO);
  gtk_tree_view_append_column(treeview, column);
}

static GtkWidget *create_actions_widget(void) {
  GtkWidget *frame = gtk_frame_new("Actions");
  GtkWidget *bbox = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);

  gtk_container_set_border_width(GTK_CONTAINER(bbox), 5);
  gtk_container_add(GTK_CONTAINER(frame), bbox);

  gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_SPREAD);
  gtk_box_set_spacing(GTK_BOX(bbox), 1);

  app->buttons->buttonStart = gtk_button_new_with_label("Start");
  g_signal_connect(app->buttons->buttonStart, "clicked", G_CALLBACK(record_start), NULL);
  gtk_container_add(GTK_CONTAINER(bbox), app->buttons->buttonStart);

  app->buttons->buttonStop = gtk_button_new_with_label("Stop");
  g_signal_connect(app->buttons->buttonStop, "clicked", G_CALLBACK(record_stop), NULL);
  gtk_container_add(GTK_CONTAINER(bbox), app->buttons->buttonStop);
  gtk_widget_set_sensitive(app->buttons->buttonStop, FALSE);

  app->buttons->buttonImport = gtk_button_new_with_label("Import");
  g_signal_connect(app->buttons->buttonImport, "clicked", G_CALLBACK(record_import), NULL);
  gtk_container_add(GTK_CONTAINER(bbox), app->buttons->buttonImport);

  app->buttons->buttonExport = gtk_button_new_with_label("Export");
  g_signal_connect(app->buttons->buttonExport, "clicked", G_CALLBACK(record_export), NULL);
  gtk_container_add(GTK_CONTAINER(bbox), app->buttons->buttonExport);
  gtk_widget_set_sensitive(app->buttons->buttonExport, FALSE);

  return frame;
}

void rowActivated(GtkTreeView *treeview, GtkTreePath *path, GtkTreeViewColumn *col, gpointer userdata) {
  GtkTreeModel *model;
  GtkTreeIter   iter;
  (void)col;
  (void)userdata;

  model = gtk_tree_view_get_model(treeview);
  if (gtk_tree_model_get_iter(model, &iter, path)) {
    GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->text));
    char str[1024];
    guint id;
    gchar *dest;

    gtk_tree_model_get(model, &iter, COLUMN_NUMBER, &id, -1);
    gtk_tree_model_get(model, &iter, COLUMN_DEST, &dest, -1);

    sprintf(str, "Packet %d info", id);
    g_print("rowActivated() id:%d\n", id);
    gtk_text_buffer_set_text(buffer, str, -1);
  }
}

static GtkWidget *create_list_widget(void) {
  GtkWidget *list = gtk_scrolled_window_new(NULL, NULL);
  app->store = gtk_list_store_new(NUM_COLUMNS,
                                           G_TYPE_UINT,
                                           G_TYPE_DOUBLE,
                                           G_TYPE_STRING,
                                           G_TYPE_STRING,
                                           G_TYPE_STRING,
                                           G_TYPE_UINT,
                                           G_TYPE_STRING);
  GtkTreeModel *model = GTK_TREE_MODEL(app->store);
  GtkWidget *treeview = gtk_tree_view_new_with_model(model);

  gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(list), GTK_SHADOW_ETCHED_IN);
  gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(list), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
  g_object_unref(model);
  gtk_container_add(GTK_CONTAINER(list), treeview);
  add_columns(GTK_TREE_VIEW(treeview));
  g_signal_connect(treeview, "row-activated", G_CALLBACK(rowActivated), NULL);
  return list;
}

static GtkWidget *create_text_widget(void) {
  app->text = gtk_text_view_new();
  GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->text));
  gtk_text_buffer_set_text(buffer, "Hello, this is some text", -1);
  gtk_text_view_set_editable(GTK_TEXT_VIEW(app->text), FALSE);
  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(app->text), FALSE);
  return app->text;
}

void rawSocketView(void) {
  g_print("rawSocketView()\n");

  gtk_window_set_title(GTK_WINDOW(app->window), "Sockets reader");
  gtk_container_set_border_width(GTK_CONTAINER(app->window), 8);

  GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
  gtk_container_add(GTK_CONTAINER(app->window), box);

  gtk_box_pack_start(GTK_BOX(box), create_actions_widget(), FALSE, FALSE, 0);
  gtk_box_pack_start(GTK_BOX(box), create_list_widget(), TRUE, TRUE, 0);
  gtk_box_pack_start(GTK_BOX(box), create_text_widget(), FALSE, FALSE, 0);

  gtk_widget_show_all(app->window);
}
