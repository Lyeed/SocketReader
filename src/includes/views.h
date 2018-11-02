#include <gtk/gtk.h>

#ifndef VIEWS_H_
#define VIEWS_H_

typedef struct {
	const guint number;
	const gchar *severity;
	const gchar *description;
} example_t;

enum {
	COLUMN_NUMBER,
	COLUMN_SEVERITY,
	COLUMN_DESCRIPTION,
	COLUMN_PULSE,
	COLUMN_ICON,
	COLUMN_ACTIVE,
	COLUMN_SENSITIVE,
	NUM_COLUMNS
};

void rawSocketView(GtkWidget *);

#endif /* VIEWS_H_ */
