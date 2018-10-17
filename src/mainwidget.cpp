#include "mainwidget.h"
#include <list>

MainWidget::MainWidget(QObject *parent): QAbstractTableModel(parent) {
}

int MainWidget::rowCount(const QModelIndex &model) const {
  (void)model;
  return 10;
}

int MainWidget::columnCount(const QModelIndex &model) const {
  (void)model;
  return 1;
}

QVariant MainWidget::data(const QModelIndex &index, int role) const {
  (void)index;
  if (role == Qt::DisplayRole) {
    return QString("Packet X");
  }
  return QVariant();
}
