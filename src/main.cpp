#include "mainwidget.h"

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    QTableView tableView;
    MainWidget MainWidget(0);

    tableView.setModel(&MainWidget);
    tableView.show();

    return a.exec();
}
