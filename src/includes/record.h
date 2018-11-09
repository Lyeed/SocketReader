#include <gtk/gtk.h>
#include "sniffer.h"

#ifndef RECORD_H_
#define RECORD_H_

void record_start(GtkWidget *, gpointer);
void record_stop(GtkWidget *, gpointer);
void record_export(GtkWidget *, gpointer);
void record_import(GtkWidget *, gpointer);

#endif /* RECORD_H_ */
