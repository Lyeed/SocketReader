#ifndef MAINWIDGET_H
#define MAINWIDGET_H

#include <QWidget>

class QTextBrowser;

class MainWidget : public QWidget {
    Q_OBJECT

public:
    explicit MainWidget(QWidget *parent = 0);
    ~MainWidget();

private:
   QTextBrowser* textBrowser_;
};

#endif // MAINWIDGET_H
