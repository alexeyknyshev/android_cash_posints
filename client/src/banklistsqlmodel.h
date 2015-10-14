#ifndef BANKLISTSQLMODEL_H
#define BANKLISTSQLMODEL_H

#include <QtSql/QSqlQueryModel>
#include <QtSql/QSqlQuery>

class BankListSqlModel : public QSqlQueryModel
{
    Q_OBJECT

public:
    enum Roles {
        IdRole = Qt::UserRole,
        NameRole,
        LicenceRole,
        NameTrRole,
        RaitingRole,
        NameTrAltRole,
        TelRole,
    };

    explicit BankListSqlModel(QString connectionName);

    int rowCount(const QModelIndex &parent = QModelIndex()) const override;

    QVariant data(const QModelIndex &item, int role) const override;

public slots:
    void setFilter(QString filterStr);

protected:
    QHash<int, QByteArray> roleNames() const override;

private:
    QHash<int, QByteArray> mRoleNames;
    QString mQueryMask;
    const QString mConnectionName;
    QSqlQuery mQuery;
};

#endif // BANKLISTSQLMODEL_H
