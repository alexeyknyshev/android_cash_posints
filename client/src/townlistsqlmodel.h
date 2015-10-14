#ifndef TOWNLISTSQLMODEL_H
#define TOWNLISTSQLMODEL_H

#include <QtGui/QStandardItemModel>
#include <QtSql/QSqlQuery>

class ServerApi;

class TownListSqlModel : public QStandardItemModel
{
    Q_OBJECT

public:
    enum Roles {
        IdRole = Qt::UserRole,
        NameRole,
        NameTrRole,
        RegionRole
    };

    explicit TownListSqlModel(QString connctionName);

    QVariant data(const QModelIndex &item, int role) const override;

public slots:
    void setFilter(QString filterStr);

    void updateFromServer(ServerApi *api, quint32 leftAttempts);

signals:
    void retryUpdate(ServerApi *api, quint32 leftAttempts);

protected:
    QHash<int, QByteArray> roleNames() const override;
    void emitRetryUpdate(ServerApi *api, quint32 leftAttempts);

private:
    QHash<int, QByteArray> mRoleNames;
    QSqlQuery mQuery;
    QSqlQuery mQueryUpdateTowns;
};

#endif // TOWNLISTSQLMODEL_H
