#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#ifndef APP_H_
#define APP_H_

int 	appOpen(void);
void 	appInit(void);
void	appRun(void);
int		appDestroy(void);

#endif /* APP_H_ */
