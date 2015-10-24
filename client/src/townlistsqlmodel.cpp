#include "townlistsqlmodel.h"

#include <QtSql/QSqlRecord>
#include <QtSql/QSqlError>
#include <QtCore/QJsonDocument>
#include <QtCore/QJsonArray>
#include <QtCore/QDebug>

#include "serverapi.h"
#include "rpctype.h"

struct Town : public RpcType<Town>
{
    QString name;
    QString nameTr;
    float longitude;
    float latitude;
    quint32 regionId;
    bool regionalCenter;

    Town()
        : longitude(0.0f),
          latitude(0.0f)
    { }

    static Town fromJsonObject(const QJsonObject &obj)
    {
        Town result = RpcType<Town>::fromJsonObject(obj);

        result.name      = obj["name"].toString();
        result.nameTr    = obj["name_tr"].toString();
        result.latitude  = obj["latitude"].toDouble();
        result.longitude = obj["longitude"].toDouble();
        result.regionId  = obj["region_id"].toInt(std::numeric_limits<int>::max());

        result.regionalCenter = obj["regional_center"].toBool();

        return result;
    }
};

struct Region : public RpcType<Region>
{
    QString name;

    static Region fromJsonObject(const QJsonObject &obj)
    {
        Region result = RpcType<Region>::fromJsonObject(obj);

        result.name = obj["name"].toString();

        return result;
    }
};

/// ================================================

TownListSqlModel::TownListSqlModel(QString connectionName, ServerApi *api)
    : ListSqlModel(connectionName, api),
      mQuery(QSqlDatabase::database(connectionName)),
      mQueryUpdateTowns(QSqlDatabase::database(connectionName)),
      mQueryUpdateRegions(QSqlDatabase::database(connectionName))
{
    setRoleName(IdRole,     "town_id");
    setRoleName(NameRole,   "town_name");
    setRoleName(NameTrRole, "town_name_tr");
    setRoleName(RegionRole, "town_region_id");
    setRoleName(CenterRole, "town_regional_center");

    if (!mQuery.prepare("SELECT id, name, name_tr FROM towns WHERE "
                        "name LIKE :filter_a or name_tr LIKE :filter_b or "
                        "region_id IN (SELECT id FROM regions WHERE name LIKE :filter_c) "
                        "ORDER BY regional_center DESC, region_id, id"))
    {
        qDebug() << "TownListSqlModel cannot prepare query:" << mQuery.lastError().databaseText();
    }

    if (!mQueryUpdateTowns.prepare("INSERT OR REPLACE INTO towns (id, name, name_tr, region_id, regional_center) "
                                   "VALUES (:id, :name, :name_tr, :region_id, :regional_center)"))
    {
        qDebug() << "TownListSqlModel cannot prepare query:" << mQueryUpdateTowns.lastError().databaseText();
    }

    if (!mQueryUpdateRegions.prepare("INSERT OR REPLACE INTO regions (id, name) "
                                     "VALUES (:id, :name)"))
    {
        qDebug() << "TownListSqlModel cannot prepare query:" << mQueryUpdateRegions.lastError().databaseText();
    }

    connect(this, SIGNAL(updateTownsIdsRequest(quint32)),
            this, SLOT(updateTownsIds(quint32)), Qt::QueuedConnection);

    connect(this, SIGNAL(townIdsUpdated(quint32)),
            this, SIGNAL(updateTownsDataRequest(quint32)));

    connect(this, SIGNAL(updateTownsDataRequest(quint32)),
            this, SLOT(updateTownsData(quint32)), Qt::QueuedConnection);

    connect(this, SIGNAL(updateRegionsRequest(quint32)),
            this, SLOT(updateRegions(quint32)), Qt::QueuedConnection);

    setFilter("");
}

QVariant TownListSqlModel::data(const QModelIndex &item, int role) const
{
    if (role < Qt::UserRole || role >= RoleLast)
    {
        return ListSqlModel::data(item, role);
    }

    return QStandardItemModel::data(index(item.row(), role - IdRole), role);
}


void TownListSqlModel::setFilterImpl(const QString &filter)
{
    for (int i = 0; i < 2; ++i) {
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

        for (int i = 0; i < RoleLast - IdRole; ++i) {
            QStandardItem *item = new QStandardItem;
            item->setData(mQuery.value(i), IdRole + i);
            items.append(item);
        }

        insertRow(row, items);
        ++row;
    }
}

static QList<int> getTownsIdList(const QJsonDocument &json)
{
    QList<int> townIdList;

    QJsonObject obj = json.object();
    QJsonValue townsVal = obj["towns"];
    if (!townsVal.isArray()) {
        qWarning() << "Json field \"towns\" is not array";
        return townIdList;
    }

    const QJsonArray arr = townsVal.toArray();

    for (const QJsonValue &val : arr) {
        static const int invalidId = -1;
        const int id = val.toInt(invalidId);
        if (id > invalidId) {
            townIdList.append(id);
        }
    }

    return townIdList;
}

static QList<Town> getTownList(const QJsonDocument &json)
{
    const QJsonObject obj = json.object();
    return Town::fromJsonArray(obj["towns"].toArray());
}

void TownListSqlModel::updateFromServerImpl(quint32 leftAttempts)
{
    if (leftAttempts == 0) {
        return;
    }

    emitUpdateTownIds(leftAttempts);
    emitUpdateRegions(leftAttempts);
}

void TownListSqlModel::updateTownsIds(quint32 leftAttempts)
{
    if (leftAttempts == 0) {
        qDebug() << "updateTownsIds: no retry attempt left";
        return;
    }

    /// Get list of towns' ids
    getServerApi()->sendRequest("/towns", {},
    [&](ServerApi::HttpStatusCode code, const QByteArray &data, bool timeOut) {
        if (timeOut) {
            emitUpdateTownIds(leftAttempts - 1);
            return;
        }

        if (code != ServerApi::HSC_Ok) {
            qWarning() << "Server request error: " << code;
            emitUpdateTownIds(leftAttempts - 1);
            return;
        }

        QJsonParseError err;
        const QJsonDocument json = QJsonDocument::fromJson(data, &err);
        if (err.error != QJsonParseError::NoError) {
            qWarning() << "Server response json parse error: " << err.errorString();
            return;
        }

        mTownsToProcess = getTownsIdList(json);
        //qDebug() << "got towns id list:" << mTownsToProcess.size();

        emitTownIdsUpdated(getAttemptsCount());
    });
}

void TownListSqlModel::updateTownsData(quint32 leftAttempts)
{
    if (leftAttempts == 0) {
        qDebug() << "updateTownsData: no retry attempt left";
        return;
    }

    if (mTownsToProcess.empty()) {
        return;
    }

    const int townsToProcess = qMin(getRequestBatchSize(), mTownsToProcess.size());
    if (townsToProcess == 0) {
        return;
    }

    QJsonArray requestTownsBatch;
    for (int i = 0; i < townsToProcess; ++i) {
        requestTownsBatch.append(mTownsToProcess.front());
        mTownsToProcess.removeFirst();
    }

    /// Get towns data from list
    getServerApi()->sendRequest("/towns", { QPair<QString, QJsonValue>("towns", requestTownsBatch) },
    [&](ServerApi::HttpStatusCode code, const QByteArray &data, bool timeOut) {
        if (timeOut) {
            for (const QJsonValue &val : requestTownsBatch) {
                const int id = val.toInt();
                if (id > 0) {
                    mTownsToProcess.append(id);
                }
            }

            emitUpdateTownData(leftAttempts - 1);
            return;
        }

        if (code != ServerApi::HSC_Ok) {
            qWarning() << "updateTownsData: http status code: " << code;
            for (const QJsonValue &val : requestTownsBatch) {
                const int id = val.toInt();
                if (id > 0) {
                    mTownsToProcess.append(id);
                }
            }

            emitUpdateTownData(leftAttempts - 1);
            return;
        }

        QJsonParseError err;
        const QJsonDocument json = QJsonDocument::fromJson(data, &err);
        if (err.error != QJsonParseError::NoError) {
            qWarning() << "updateTownsData: response parse error: " << err.errorString();
            return;
        }

        const QList<Town> townList = getTownList(json);
        if (townList.isEmpty()) {
            qWarning() << "updateTownsData: response is empty\n"
                       << QString::fromUtf8(data);
        }

        for (const Town &town : townList) {
            mQueryUpdateTowns.bindValue(0, town.id);
            mQueryUpdateTowns.bindValue(1, town.name);
            mQueryUpdateTowns.bindValue(2, town.nameTr);
            mQueryUpdateTowns.bindValue(3, town.regionId);
            mQueryUpdateTowns.bindValue(4, town.regionalCenter);

            if (!mQueryUpdateTowns.exec()) {
                qWarning() << "updateTownsData: failed to update 'towns' table";
                qWarning() << "updateTownsData: " << mQueryUpdateTowns.lastError().databaseText();
            }
        }

        emitUpdateTownData(getAttemptsCount());
    });
}

void TownListSqlModel::updateRegions(quint32 leftAttempts)
{
    if (leftAttempts == 0) {
        qDebug() << "updateRegions: no retry attempt left";
        return;
    }

    getServerApi()->sendRequest("/regions", {},
    [&](ServerApi::HttpStatusCode code, const QByteArray &data, bool timeOut) {
        if (timeOut) {
            emitUpdateRegions(leftAttempts - 1);
            return;
        }

        if (code != ServerApi::HSC_Ok) {
            emitUpdateRegions(leftAttempts - 1);
            qWarning() << "Server request error: " << code;
            return;
        }

        QJsonParseError err;
        const QJsonDocument json = QJsonDocument::fromJson(data, &err);
        if (err.error != QJsonParseError::NoError) {
            qWarning() << "Server response json parse error: " << err.errorString();
            return;
        }

        const QJsonObject obj = json.object();
        const QJsonValue regionsJson = obj["regions"];
        if (!regionsJson.isArray()) {
            qWarning() << "Server response is not json array";
            return;
        }

        const QList<Region> regions = Region::fromJsonArray(regionsJson.toArray());
        for (const Region &reg : regions) {
            mQueryUpdateRegions.bindValue(0, reg.id);
            mQueryUpdateRegions.bindValue(1, reg.name);

            if (!mQueryUpdateRegions.exec()) {
                qWarning() << "syncTowns: failed to update 'regions' table";
                qWarning() << "syncTowns: " << mQueryUpdateRegions.lastError().databaseText();
            }
        }
    });
}
