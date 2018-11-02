#include "app.h"
#include "views.h"

static GtkWidget *appInit(void) {
	gtk_init(NULL, NULL);
	GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_screen(GTK_WINDOW(window), gtk_widget_get_screen(NULL));
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    g_signal_connect(window, "delete-event", G_CALLBACK(gtk_main_quit), NULL);
	return window;
}

static int appDestroy(GtkWidget *window) {
	gtk_widget_destroy(window);
	window = NULL;
	return 0;
}

static void appRun(GtkWidget *window) {
    rawSocketView(window);
}

int appOpen() {
	GtkWidget *mainWindow = appInit();
	appRun(mainWindow);
    return appDestroy(mainWindow);
}
