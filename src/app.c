#include "app.h"
#include "views.h"
#include "sniffer.h"

static GtkWidget *appInit(void) {
  GtkWidget *window;

	gtk_init(NULL, NULL);
	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_screen(GTK_WINDOW(window), gtk_widget_get_screen(NULL));
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
  g_signal_connect(window, "delete-event", G_CALLBACK(gtk_main_quit), NULL);
  gtk_window_set_default_size(GTK_WINDOW(window), 512, 512);
  gtk_widget_show(window);
	return window;
}

static int appDestroy(GtkWidget *window) {
	gtk_widget_destroy(window);
  gtk_main_quit();
	window = NULL;
	return 0;
}

static void appRun(GtkWidget *window) {
  raw_packet_t *raw = NULL;
  // pthread_t thread;

  sniffer(&raw);
  // pthread_create(&thread, NULL, sniffer, &raw);
  rawSocketView(window, raw);
}

int appOpen() {
	GtkWidget *mainWindow = appInit();

	appRun(mainWindow);
  return appDestroy(mainWindow);
}
