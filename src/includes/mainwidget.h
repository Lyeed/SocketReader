#ifndef MAINWIDGET_H
#define MAINWIDGET_H

#include <QWidget>
#include <QAbstractTableModel>
#include <QApplication>
#include <QTableView>

class MainWidget : public QAbstractTableModel {
    Q_OBJECT

public:
    MainWidget(QObject *parent);
    int rowCount(const QModelIndex &parent = QModelIndex()) const override ;
    int columnCount(const QModelIndex &parent = QModelIndex()) const override;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
};

#endif /* MAINWIDGET_H */
