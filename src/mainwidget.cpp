#include <QtWidgets>
#include "mainwidget.h"

MainWidget::MainWidget(QWidget *parent): QWidget(parent) {
   textBrowser_ = new QTextBrowser();

   QGridLayout *mainLayout = new QGridLayout;
   mainLayout->addWidget(textBrowser_,1,0);
   setLayout(mainLayout);
   setWindowTitle(tr("Choose an interface"));
}

MainWidget::~MainWidget() {
   delete textBrowser_;
}
