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
  COLUMN_PULSE,
  COLUMN_ICON,
  COLUMN_ACTIVE,
  COLUMN_SENSITIVE,
  NUM_COLUMNS
};

void rawSocketView(GtkWidget *, raw_packet_t **);

#endif /* VIEWS_H_ */
