#ifndef BANKLISTSQLMODEL_H
#define BANKLISTSQLMODEL_H

#include <QtSql/QSqlQuery>

#include "listsqlmodel.h"

class BankListSqlModel : public ListSqlModel
{
    Q_OBJECT

    friend class SearchEngine;

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
        MineRole,
        IcoPathRole,

        RoleLast
    };

    BankListSqlModel(const QString &connectionName,
                     ServerApi *api,
                     IcoImageProvider *imageProvider,
                     QSettings *settings);

    QVariant data(const QModelIndex &item, int role) const override;

    bool setData(const QModelIndex &index,
                 const QVariant &value,
                 int role) override;

signals:
    void updateBanksIdsRequest(quint32 leftAttempts);
    void updateBanksDataRequest(quint32 leftAttempts);
    void updateBankIcoRequest(quint32 leftAttempts, quint32 bankId);

    void bankIdsUpdated(quint32 leftAttempts);
    void bankIcoUpdated(quint32 bankId);

protected:
    void updateFromServerImpl(quint32 leftAttempts) override;
    void setFilterImpl(const QString &filter) override;

    int getLastRole() const override { return RoleLast; }

    QSqlQuery &getQuery() override { return mQuery; }

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
    void emitBankIcoUpdated(quint32 bankId)
    { emit bankIcoUpdated(bankId); }

    QList<int> mBanksToProcess;

    QSqlQuery mQuery;
    QSqlQuery mQueryUpdateBanks;
    QSqlQuery mQueryUpdateBankIco;
    QSqlQuery mQuerySetBankMine;
};

#endif // BANKLISTSQLMODEL_H
