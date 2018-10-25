#include <ncurses.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#ifndef APP_H_
#define APP_H_

int 	appOpen(void);
void 	appInit(void);
void	appLoop(void);
int		appDestroy(void);

#endif /* APP_H_ */
