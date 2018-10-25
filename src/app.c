#include "app.h"

void appInit() {
	initscr();
}

int appDestroy() {
	endwin();
	return 0;
}

void appLoop() {
	while (true) {
		clear();
	    time_t mytime = time(0);
	    char * time_str = ctime(&mytime);
	    time_str[strlen(time_str)-1] = '\0';
		printw("Date is %s", time_str);
		refresh();
		sleep(1);
	}
}

int appOpen() {
	appInit();
	appLoop();
    return appDestroy();
}
