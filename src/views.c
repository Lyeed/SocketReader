#include "views.h"

const example_t example[] = {
	{ 60482, "Normal",     "scrollable notebooks and hidden tabs" },
	{ 60620, "Critical",   "gdk_window_clear_area (gdkwindow-win32.c) is not thread-safe" },
	{ 50214, "Major",      "Xft support does not clean up correctly" },
	{ 52877, "Major",      "GtkFileSelection needs a refresh method. " },
	{ 56070, "Normal",     "Can't click button after setting in sensitive" },
	{ 56355, "Normal",     "GtkLabel - Not all changes propagate correctly" },
	{ 50055, "Normal",     "Rework width/height computations for TreeView" },
	{ 58278, "Normal",     "gtk_dialog_set_response_sensitive() doesn't work" },
	{ 55767, "Normal",     "Getters for all setters" },
	{ 56925, "Normal",     "Gtkcalender size" },
	{ 56221, "Normal",     "Selectable label needs right-click copy menu" },
	{ 50939, "Normal",     "Add shift clicking to GtkTextView" },
	{ 6112,  "Enhancement","netscape-like collapsable toolbars" },
	{ 1,     "Normal",     "First bug :=)" },
};

static GtkTreeModel *create_model(void) {
	GtkTreeIter iter;
	GtkListStore *store = gtk_list_store_new(NUM_COLUMNS,
							G_TYPE_UINT,
							G_TYPE_STRING,
							G_TYPE_STRING,
							G_TYPE_UINT,
							G_TYPE_STRING,
							G_TYPE_BOOLEAN,
							G_TYPE_BOOLEAN);

	for (unsigned int i = 0; i < G_N_ELEMENTS(example); i++) {
		gchar *icon_name;
		gboolean sensitive;

		if (i == 1 || i == 3) {
			icon_name = "battery-caution-charging-symbolic";
		} else {
			icon_name = NULL;
		}

		if (i == 3) {
			sensitive = FALSE;
		} else {
			sensitive = TRUE;
		}

		gtk_list_store_append(store, &iter);
		gtk_list_store_set(store, &iter,
						  COLUMN_NUMBER, example[i].number,
						  COLUMN_SEVERITY, example[i].severity,
						  COLUMN_DESCRIPTION, example[i].description,
						  COLUMN_PULSE, 0,
						  COLUMN_ICON, icon_name,
						  COLUMN_ACTIVE, FALSE,
						  COLUMN_SENSITIVE, sensitive,
						  -1);
	}

	return GTK_TREE_MODEL(store);
}

static void add_columns(GtkTreeView *treeview) {
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *column;

	/* column for bug numbers */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Bug number", renderer, "text", COLUMN_NUMBER, NULL);
	gtk_tree_view_column_set_sort_column_id(column, COLUMN_NUMBER);
	gtk_tree_view_append_column(treeview, column);

	/* column for severities */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Severity", renderer, "text", COLUMN_SEVERITY, NULL);
	gtk_tree_view_column_set_sort_column_id(column, COLUMN_SEVERITY);
	gtk_tree_view_append_column(treeview, column);

	/* column for description */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Description", renderer, "text", COLUMN_DESCRIPTION, NULL);
	gtk_tree_view_column_set_sort_column_id(column, COLUMN_DESCRIPTION);
	gtk_tree_view_append_column(treeview, column);
}

static void callback(GtkWidget *widget, gpointer data) {
	(void)widget;
    g_print ("Hello again - %s was pressed\n", (char *)data);
}

static GtkWidget *create_actions_widget(void) {
	GtkWidget *frame = gtk_frame_new("Actions");
	GtkWidget *bbox = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
	GtkWidget *button;

	gtk_container_set_border_width(GTK_CONTAINER(bbox), 5);
	gtk_container_add(GTK_CONTAINER(frame), bbox);

	gtk_button_box_set_layout(GTK_BUTTON_BOX(bbox), GTK_BUTTONBOX_SPREAD);
	gtk_box_set_spacing(GTK_BOX(bbox), 1);

	button = gtk_button_new_with_label("Start");
    g_signal_connect(button, "clicked", G_CALLBACK(callback), (gpointer) "cool button");
	gtk_container_add(GTK_CONTAINER(bbox), button);

	button = gtk_button_new_with_label("Stop");
	g_signal_connect(button, "clicked", G_CALLBACK(callback), (gpointer) "cool button");
	gtk_container_add(GTK_CONTAINER(bbox), button);

	button = gtk_button_new_with_label("Import");
	g_signal_connect(button, "clicked", G_CALLBACK(callback), (gpointer) "cool button");
	gtk_container_add(GTK_CONTAINER(bbox), button);

	button = gtk_button_new_with_label("Export");
	g_signal_connect(button, "clicked", G_CALLBACK(callback), (gpointer) "cool button");
	gtk_container_add(GTK_CONTAINER(bbox), button);

	return frame;
}

static GtkWidget *create_list_widget(void) {
	GtkWidget *list = gtk_scrolled_window_new(NULL, NULL);
	GtkTreeModel *model = create_model();
	GtkWidget *treeview = gtk_tree_view_new_with_model(model);

	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(list), GTK_SHADOW_ETCHED_IN);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(list), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);

	gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(treeview), TRUE);
	gtk_tree_view_set_search_column(GTK_TREE_VIEW(treeview), COLUMN_DESCRIPTION);

	g_object_unref(model);
	gtk_container_add(GTK_CONTAINER(list), treeview);

	add_columns(GTK_TREE_VIEW(treeview));
	return list;
}

void rawSocketView(GtkWidget *window) {
	gtk_window_set_title(GTK_WINDOW(window), "Sockets reader");
	gtk_container_set_border_width(GTK_CONTAINER(window), 8);

	GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
	gtk_container_add(GTK_CONTAINER(window), box);

	gtk_box_pack_start(GTK_BOX(box), create_actions_widget(), FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(box), create_list_widget(), TRUE, TRUE, 0);

	gtk_window_set_default_size(GTK_WINDOW(window), 512, 512);

	gtk_widget_show(window);
	gtk_widget_show_all(window);
	gtk_main();
}
