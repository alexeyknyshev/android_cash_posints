#include "banklistsqlmodel.h"

#include <QtSql/QSqlRecord>
#include <QtSql/QSqlError>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonArray>
#include <QtCore/QFile>
#include <QtCore/QDebug>

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

        return result;
    }
};

/// ================================================

BankListSqlModel::BankListSqlModel(QString connectionName, ServerApi *api)
    : ListSqlModel(connectionName, api),
      mQuery(QSqlDatabase::database(connectionName)),
      mQueryUpdateBanks(QSqlDatabase::database(connectionName))
{
    setRoleName(IdRole,        "bank_id");
    setRoleName(NameRole,      "bank_name");
    setRoleName(LicenceRole,   "bank_licence");
    setRoleName(NameTrRole,    "bank_name_tr");
    setRoleName(RatingRole,    "bank_rating");
    setRoleName(NameTrAltRole, "bank_name_tr_alt");
    setRoleName(TelRole,       "bank_tel");
    setRoleName(IcoPath,       "bank_ico_path");


    if (!mQuery.prepare("SELECT id, name, licence, name_tr, rating, town, name_tr_alt, tel FROM banks"
                        " WHERE"
                        "       name LIKE :name"
                        " or licence LIKE :licence"
                        " or name_tr LIKE :name_tr"
                        " or    town LIKE :town"
                        " or     tel LIKE :tel"
                        " ORDER BY rating"))
    {
        qDebug() << "BankListSqlModel cannot prepare query:" << mQuery.lastError().databaseText();
    }

    if (!mQueryUpdateBanks.prepare("INSERT OR REPLACE INTO banks (id, name, licence, name_tr, rating, name_tr_alt, town, tel) "
                                   "VALUES (:id, :name, :licence, :name_tr, :rating, :name_tr_alt, :town, :tel)"))
    {
        qDebug() << "BankListSqlModel cannot prepare query:" << mQuery.lastError().databaseText();
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
        for (int i = 0; i < IcoPath - IdRole; ++i) {
            item->setData(mQuery.value(i), IdRole + i);
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

        qDebug() << "updateBankIco: bankIco: " << jsonObj["bank_id"].toString();

        const quint32 bankId = jsonObj["bank_id"].toInt();
        if (bankId == 0) {
            qWarning() << "updateBankIco: invlid bankId";
            return;
        }

        QString icoData = jsonObj["ico_data"].toString();

        const QString bankIdStr = QString::number(bankId);
        QFile file("./data/banks/ico/" + bankIdStr + ".svg");
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            qWarning() << "updateBankIco: cannot open file for writting: " << file.fileName();
            return;
        }
        QTextStream out(&file);
        out << icoData;
        out.flush();
        file.close();

        QList<QStandardItem *> items = findItems(bankIdStr);
        if (items.empty()) {
            qWarning() << "updateBankIco: cannot find bank record:" << bankId;
            return;
        }

        if (items.size() > 1) {
            qWarning() << "updateBankIco: found " << items.size() << " matching banks records => "
                       << "updating all";
        }

        for (QStandardItem *item : items) {
            item->setData(file.fileName());
        }
    });
}
