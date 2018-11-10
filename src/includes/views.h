#include <gtk/gtk.h>
#include "sniffer.h"

#ifndef VIEWS_H_
#define VIEWS_H_

enum {
	COLUMN_NUMBER,
  COLUMN_TIME,
	COLUMN_SOURCE,
	COLUMN_DEST,
  COLUMN_PROTOCOL,
  COLUMN_LENGTH,
  COLUMN_INFO,
  COLUMN_PULSE,
  COLUMN_ICON,
  COLUMN_ACTIVE,
  COLUMN_SENSITIVE,
  NUM_COLUMNS
};

void rawSocketView(void);
void fill_list(raw_packet_t *);
void rowActivated(GtkTreeView *, GtkTreePath *, GtkTreeViewColumn *, gpointer);

#endif /* VIEWS_H_ */
