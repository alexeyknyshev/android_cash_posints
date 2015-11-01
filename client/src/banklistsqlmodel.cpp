#include "banklistsqlmodel.h"
#include "icoimageprovider.h"

#include <QtSql/QSqlRecord>
#include <QtSql/QSqlError>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonArray>
#include <QtCore/QFile>
#include <QtCore/QDebug>
#include <QtCore/QSettings>

#include "rpctype.h"
#include "serverapi.h"

struct Bank : public RpcType<Bank>
{
    QString name;
    QString nameTr;
    QString nameTrAlt;
    QString town;
    QString tel;
    quint32 licence;
    quint32 rating;
    quint32 mine;

    Bank()
        : licence(0),
          rating(0)
    { }

    static Bank fromJsonObject(const QJsonObject &obj)
    {
        Bank result = RpcType<Bank>::fromJsonObject(obj);

        result.name      = obj["name"].toString();
        result.nameTr    = obj["name_tr"].toString();
        result.nameTrAlt = obj["name_tr_alt"].toString();
        result.town      = obj["town"].toString();
        result.tel       = obj["tel"].toString();
        result.licence   = obj["licence"].toInt();
        result.rating    = obj["rating"].toInt();
        result.mine      = obj["mine"].toInt();

        return result;
    }
};

/// ================================================

BankListSqlModel::BankListSqlModel(const QString &connectionName,
                                   ServerApi *api,
                                   IcoImageProvider *imageProvider,
                                   QSettings *settings)
    : ListSqlModel(connectionName, api, imageProvider, settings),
      mQuery(QSqlDatabase::database(connectionName)),
      mQueryUpdateBanks(QSqlDatabase::database(connectionName)),
      mQueryUpdateBankIco(QSqlDatabase::database(connectionName)),
      mQuerySetBankMine(QSqlDatabase::database(connectionName))
{
    setRowCount(600);

    setRoleName(IdRole,        "bank_id");
    setRoleName(NameRole,      "bank_name");
    setRoleName(LicenceRole,   "bank_licence");
    setRoleName(NameTrRole,    "bank_name_tr");
    setRoleName(RatingRole,    "bank_rating");
    setRoleName(NameTrAltRole, "bank_name_tr_alt");
    setRoleName(TelRole,       "bank_tel");
    setRoleName(MineRole,      "bank_is_mine");
    setRoleName(IcoPathRole,   "bank_ico_path");


    if (!mQuery.prepare("SELECT id, name, licence, name_tr, rating, town, name_tr_alt, tel, mine, ico_path FROM banks"
                        " WHERE"
                        "       name LIKE :name"
                        " or licence LIKE :licence"
                        " or name_tr LIKE :name_tr"
                        " or    town LIKE :town"
                        " or     tel LIKE :tel"
                        " ORDER BY mine DESC, rating"))
    {
        qDebug() << "BankListSqlModel cannot prepare query:" << mQuery.lastError().databaseText();
    }

    if (!mQueryUpdateBanks.prepare("INSERT OR REPLACE INTO banks (id, name, licence, name_tr, rating, name_tr_alt, town, tel, mine)"
                                   "VALUES (:id, :name, :licence, :name_tr, :rating, :name_tr_alt, :town, :tel, :mine)"))
    {
        qDebug() << "BankListSqlModel cannot prepare query:" << mQueryUpdateBanks.lastError().databaseText();
    }

    if (!mQueryUpdateBankIco.prepare("UPDATE banks SET ico_path = :ico_path WHERE id = :bank_id")) {
        qDebug() << "BankListSqlModel cannot prepare query:" << mQueryUpdateBankIco.lastError().databaseText();
    }

    if (!mQuerySetBankMine.prepare("UPDATE banks SET mine = :mine WHERE id = :bank_id")) {
        qDebug() << "BankListSqlModel cannot prepare query:" << mQuerySetBankMine.lastError().databaseText();
    }

    connect(this, SIGNAL(updateBanksIdsRequest(quint32)),
            this, SLOT(updateBanksIds(quint32)), Qt::QueuedConnection);

    connect(this, SIGNAL(bankIdsUpdated(quint32)),
            this, SIGNAL(updateBanksDataRequest(quint32)), Qt::QueuedConnection);

    connect(this, SIGNAL(updateBanksDataRequest(quint32)),
            this, SLOT(updateBanksData(quint32)), Qt::QueuedConnection);

    connect(this, SIGNAL(updateBankIcoRequest(quint32,quint32)),
            this, SLOT(updateBankIco(quint32,quint32)), Qt::QueuedConnection);

    setFilter("");
}

QVariant BankListSqlModel::data(const QModelIndex &item, int role) const
{
    if (role < Qt::UserRole || role >= RoleLast)
    {
        return ListSqlModel::data(item, role);
    }

    return QStandardItemModel::data(index(item.row(), 0), role);
}

bool BankListSqlModel::setData(const QModelIndex &index,
                               const QVariant &value,
                               int role)
{
    if (role == MineRole) {
        const int mine = value.toInt() == 0 ? 0 : 1;
        quint32 bankId = index.data(IdRole).toInt();
        if (!bankId) {
            qDebug() << "invalid bank id";
            return false;
        }

        qDebug() << "update mine: [" << bankId << ": " << mine << "]";
        mQuerySetBankMine.bindValue(0, mine);
        mQuerySetBankMine.bindValue(1, bankId);
        if (!mQuerySetBankMine.exec()) {
            qDebug() << "BankListSqlModel cannot local update mine banks";
        }

        const QString bankIdStr = QString::number(bankId);

        getSettings()->beginGroup("mybanks");
        if (mine == 1) {
            getSettings()->setValue(bankIdStr, mine);
        } else {
            getSettings()->remove(bankIdStr);
        }
        getSettings()->endGroup();

        QJsonObject json;
        json["mine"] = QJsonValue(mine);
        /// TODO: add session
        getServerApi()->sendRequest("/bank/" + bankIdStr + "/mine", json,
        [&](ServerApi::HttpStatusCode code, const QByteArray &data, bool timeOut) {

        });
    }
    return ListSqlModel::setData(index, value, role);
}

void BankListSqlModel::updateFromServerImpl(quint32 leftAttempts)
{
    if (leftAttempts == 0) {
        return;
    }

    emitUpdateBanksIds(leftAttempts);
}

void BankListSqlModel::setFilterImpl(const QString &filter)
{
    for (int i = 0; i < 5; ++i) {
        mQuery.bindValue(i, filter);
    }

    if (!mQuery.exec()) {
        qCritical() << mQuery.lastError().databaseText();
        Q_ASSERT_X(false, "TownListSqlModel::setFilter", "sql query error");
    }

    clear();
    int row = 0;
    while (mQuery.next())
    {
        QList<QStandardItem *> items;

        QStandardItem *item = new QStandardItem;
        for (int i = 0; i < RoleLast - IdRole; ++i) {
            item->setData(mQuery.value(i), IdRole + i);
//            qDebug() << mQuery.value(i);
        }
        items.append(item);

        insertRow(row, items);
        ++row;
    }
}

static QList<int> getBanksIdList(const QJsonDocument &json)
{
    QList<int> bankIdList;

    QJsonObject obj = json.object();
    QJsonValue banksVal = obj["banks"];
    if (!banksVal.isArray()) {
        qWarning() << "Json field \"banks\" is not array";
        return bankIdList;
    }

    const QJsonArray arr = banksVal.toArray();

    for (const QJsonValue &val : arr) {
        static const int invalidId = -1;
        const int id = val.toInt(invalidId);
        if (id > invalidId) {
            bankIdList.append(id);
        }
    }

    return bankIdList;
}

static QList<Bank> getBankList(const QJsonDocument &json)
{
    const QJsonObject obj = json.object();
    return Bank::fromJsonArray(obj["banks"].toArray());
}

void BankListSqlModel::updateBanksIds(quint32 leftAttempts)
{
    if (leftAttempts == 0) {
        qDebug() << "updateBanksIds: no retry attempt left";
        return;
    }

    /// Get list of banks' ids
    getServerApi()->sendRequest("/banks", {},
    [&](ServerApi::HttpStatusCode code, const QByteArray &data, bool timeOut) {
        if (timeOut) {
            emitUpdateBanksIds(leftAttempts - 1);
            return;
        }

        if (code != ServerApi::HSC_Ok) {
            qWarning() << "Server request error: " << code;
            emitUpdateBanksIds(leftAttempts - 1);
            return;
        }

        QJsonParseError err;
        const QJsonDocument json = QJsonDocument::fromJson(data, &err);
        if (err.error != QJsonParseError::NoError) {
            qWarning() << "Server response json parse error: " << err.errorString();
            return;
        }

        mBanksToProcess = getBanksIdList(json);
        emitBankIdsUpdated(getAttemptsCount());
    });
}

void BankListSqlModel::updateBanksData(quint32 leftAttempts)
{
    if (leftAttempts == 0) {
        qDebug() << "updateBanksData: no retry attempt left";
        return;
    }

    if (mBanksToProcess.empty()) {
        return;
    }

    const int banksToProcess = qMin(getRequestBatchSize(), mBanksToProcess.size());
    if (banksToProcess == 0) {
        return;
    }

    QJsonArray requestBanksBatch;
    for (int i = 0; i < banksToProcess; ++i) {
        requestBanksBatch.append(mBanksToProcess.front());
        mBanksToProcess.removeFirst();
    }

    /// Get banks data from list
    getServerApi()->sendRequest("/banks", { QPair<QString, QJsonValue>("banks", requestBanksBatch) },
    [&](ServerApi::HttpStatusCode code, const QByteArray &data, bool timeOut) {
        if (timeOut) {
            for (const QJsonValue &val : requestBanksBatch) {
                const int id = val.toInt();
                if (id > 0) {
                    mBanksToProcess.append(id);
                }
            }

            emitUpdateBanksData(leftAttempts - 1);
            return;
        }

        if (code != ServerApi::HSC_Ok) {
            qWarning() << "updateBanksData: http status code: " << code;
            for (const QJsonValue &val : requestBanksBatch) {
                const int id = val.toInt();
                if (id > 0) {
                    mBanksToProcess.append(id);
                }
            }

            emitUpdateBanksData(leftAttempts - 1);
            return;
        }

        QJsonParseError err;
        const QJsonDocument json = QJsonDocument::fromJson(data, &err);
        if (err.error != QJsonParseError::NoError) {
            qWarning() << "updateBanksData: response parse error: " << err.errorString();
            return;
        }

        const QList<Bank> bankList = getBankList(json);
        if (bankList.isEmpty()) {
            qWarning() << "updateBanksData: response is empty\n"
                       << QString::fromUtf8(data);
        }

        for (const Bank &bank : bankList) {
            mQueryUpdateBanks.bindValue(0, bank.id);
            mQueryUpdateBanks.bindValue(1, bank.name);
            mQueryUpdateBanks.bindValue(2, bank.licence);
            mQueryUpdateBanks.bindValue(3, bank.nameTr);
            mQueryUpdateBanks.bindValue(4, bank.rating);
            mQueryUpdateBanks.bindValue(5, bank.nameTrAlt);
            mQueryUpdateBanks.bindValue(6, bank.town);
            mQueryUpdateBanks.bindValue(7, bank.tel);

            if (bank.mine == 1) {
                getSettings()->beginGroup("mybanks");
                getSettings()->setValue(QString::number(bank.id), bank.mine);
                getSettings()->endGroup();
                mQueryUpdateBanks.bindValue(8, bank.mine);
            } else {
                getSettings()->beginGroup("mybanks");
                const int mine = getSettings()->value(QString::number(bank.id), 0).toInt();
                getSettings()->endGroup();
                mQueryUpdateBanks.bindValue(8, mine);
            }

            if (!mQueryUpdateBanks.exec()) {
                qWarning() << "updateBanksData: failed to update 'banks' table";
                qWarning() << "updateBanksData: " << mQueryUpdateBanks.lastError().databaseText();
            }

            emitUpdateBankIco(getAttemptsCount(), bank.id);
        }

        emitUpdateBanksData(getAttemptsCount());
    });
}

void BankListSqlModel::updateBankIco(quint32 leftAttempts, quint32 bankId)
{
    if (leftAttempts == 0) {
        qDebug() << "updateBankIco: no retry attempt left";
        return;
    }

    const QString requestPath = "/bank/" + QString::number(bankId) + "/ico";
    getServerApi()->sendRequest(requestPath, {},
    [&, bankId](ServerApi::HttpStatusCode code, const QByteArray &data, bool timeOut) {
        if (timeOut) {
            emitUpdateBankIco(leftAttempts - 1, bankId);
            return;
        }

        if (code != ServerApi::HSC_Ok) {
            qWarning() << "updateBankIco: http status code: " << code;

            emitUpdateBankIco(leftAttempts - 1, bankId);
            return;
        }

        QJsonParseError err;
        const QJsonDocument json = QJsonDocument::fromJson(data, &err);
        if (err.error != QJsonParseError::NoError) {
            qWarning() << "updateBankIco: response parse error: " << err.errorString();
            return;
        }

        const QJsonObject jsonObj = json.object();
        if (jsonObj.isEmpty()) {
            qWarning() << "updateBankIco: empty json object in response: " << data;
            return;
        }

        const int bankId = jsonObj["bank_id"].toInt();
        if (bankId == 0) {
            qWarning() << "updateBankIco: invlid bankId";
            return;
        }

        QString icoData = jsonObj["ico_data"].toString();

        const QString bankIcoPath = "ico/bank/" + QString::number(bankId);
        if (!getIcoImageProvider()->loadSvgImage("bank/" + QString::number(bankId), icoData.toUtf8())) {
            qWarning() << "updateBankIco: cannot load ico into ImageProvider: " << bankId;
            return;
        }

        mQueryUpdateBankIco.bindValue(0, bankIcoPath);
        mQueryUpdateBankIco.bindValue(1, bankId);

        if (!mQueryUpdateBankIco.exec()) {
            qWarning() << "updateBanksData: failed to update 'banks' table. Ico for bank:" << bankId;
            qWarning() << "updateBanksData: " << mQueryUpdateBankIco.lastError().databaseText();
            return;
        }

        emitBankIcoUpdated(bankId);
    });
}
