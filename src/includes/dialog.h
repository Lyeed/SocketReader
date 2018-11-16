#include "app.h"

#ifndef DIALOG_H_
#define DIALOG_H_

void textDialogClose(GtkWidget *widget);
void textDialogOpen(GtkWindow *parent);
void packetDialogOpen(const raw_packet_t *);

#endif /* DIALOG_H_ */
