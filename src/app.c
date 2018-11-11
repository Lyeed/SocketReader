#include "app.h"
#include "views.h"

void *appDestroy(void) {
  if (app) {
    if (app->window) {
      gtk_widget_destroy(app->window);
    }
  }
  gtk_main_quit();
  return 0;
}

static void appInit(void) {
	gtk_init(NULL, NULL);
  app = malloc(sizeof(app_t));
  if (!app) {
    g_printerr("app malloc() failed\n");
    exit(-1);
  }
	app->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  app->buttons = malloc(sizeof(buttons_t));
  if (!app->buttons) {
    g_printerr("app->buttons malloc() failed\n");
    exit(-1);
  }
  app->raw = NULL;
  app->store = NULL;
  app->run = 1;
	gtk_window_set_screen(GTK_WINDOW(app->window), gtk_widget_get_screen(NULL));
	g_signal_connect(app->window, "destroy", G_CALLBACK(appDestroy), NULL);
  g_signal_connect(app->window, "delete-event", G_CALLBACK(appDestroy), NULL);
  gtk_window_set_default_size(GTK_WINDOW(app->window), 1024, 1024);
  gtk_widget_show(app->window);
}

static void appRun(void) {
  rawSocketView();
  gtk_main();
}

void appOpen(void) {
	appInit();
	appRun();
}
