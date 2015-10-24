#ifndef BANKLISTSQLMODEL_H
#define BANKLISTSQLMODEL_H

#include <QtSql/QSqlQuery>

#include "listsqlmodel.h"

class BankListSqlModel : public ListSqlModel
{
    Q_OBJECT

public:
    enum Roles {
        IdRole = Qt::UserRole,
        NameRole,
        LicenceRole,
        NameTrRole,
        RatingRole,
        RegionName,
        NameTrAltRole,
        TelRole,
        IcoPath,

        RoleLast
    };

    BankListSqlModel(QString connectionName, ServerApi *api);

    QVariant data(const QModelIndex &item, int role) const override;

signals:
    void updateBanksIdsRequest(quint32 leftAttempts);
    void updateBanksDataRequest(quint32 leftAttempts);
    void updateBankIcoRequest(quint32 leftAttempts, quint32 bankId);

    void bankIdsUpdated(quint32 leftAttempts);

protected:
    void updateFromServerImpl(quint32 leftAttempts) override;
    void setFilterImpl(const QString &filter) override;

    int getLastRole() const override { return RoleLast; }

private slots:
    void updateBanksIds(quint32 leftAttempts);
    void updateBanksData(quint32 leftAttempts);
    void updateBankIco(quint32 leftAttempts, quint32 bankId);

private:
    void emitUpdateBanksIds(quint32 leftAttempts)
    { emit updateBanksIdsRequest(leftAttempts); }
    void emitBankIdsUpdated(quint32 leftAttempts)
    { emit bankIdsUpdated(leftAttempts); }
    void emitUpdateBanksData(quint32 leftAttempts)
    { emit updateBanksDataRequest(leftAttempts); }
    void emitUpdateBankIco(quint32 leftAttempts, quint32 bankId)
    { emit updateBankIcoRequest(leftAttempts, bankId); }

    QList<int> mBanksToProcess;

    QSqlQuery mQuery;
    QSqlQuery mQueryUpdateBanks;
};

#endif // BANKLISTSQLMODEL_H
