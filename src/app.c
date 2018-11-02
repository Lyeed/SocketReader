#include "app.h"
#include "views.h"

void appInit() {
}

int appDestroy() {
	return 0;
}

void appRun() {
    rawSocketView();
}

int appOpen() {
	appInit();
	appRun();
    return appDestroy();
}
