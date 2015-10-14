#include "townlistsqlmodel.h"

#include "serverapi.h"

#include <QtSql/QSqlRecord>
#include <QtSql/QSqlError>
#include <QDebug>
#include <QJsonDocument>
#include <QJsonArray>

TownListSqlModel::TownListSqlModel(QString connectionName)
    : QStandardItemModel(0, 4, nullptr),
      mQuery(QSqlDatabase::database(connectionName)),
      mQueryUpdateTowns(QSqlDatabase::database(connectionName))
{
    mRoleNames[IdRole]     = "town_id";
    mRoleNames[NameRole]   = "town_name";
    mRoleNames[NameTrRole] = "town_name_tr";
    mRoleNames[RegionRole] = "town_region_id";

    mRoleNames[RegionRole + 1] = "index";

    if (!mQuery.prepare("SELECT id, name, name_tr FROM towns WHERE "
                        "name LIKE :filter_a or name_tr LIKE :filter_b or "
                        "region_id IN (SELECT id FROM regions WHERE name LIKE :filter_c) "
                        "ORDER BY region_id, id"))
    {
        qDebug() << "TownListSqlModel cannot prepare query:" << mQuery.lastError().databaseText();
    }

    if (!mQueryUpdateTowns.prepare("INSERT INTO towns (id, name, name_tr, region_id) "
                                   "VALUES (:id, :name, :name_tr, :region_id)"))
    {
        qDebug() << "TownListSqlModel cannot prepare query:" << mQueryUpdateTowns.lastError().databaseText();
    }

    setFilter("");
}

QHash<int, QByteArray> TownListSqlModel::roleNames() const
{
    return mRoleNames;
}

QVariant TownListSqlModel::data(const QModelIndex &item, int role) const
{
    if (role == RegionRole + 1)
    {
        return item.row();
    }

    QVariant data;

    switch (role)
    {
    case IdRole:     data = QStandardItemModel::data(index(item.row(), 0), NameRole); break;
    case NameRole:   data = QStandardItemModel::data(index(item.row(), 1), NameRole); break;
    case NameTrRole: data = QStandardItemModel::data(index(item.row(), 2), NameRole); break;
    case RegionRole: data = QStandardItemModel::data(index(item.row(), 3), NameRole); break;
    }

    return data;
}


void TownListSqlModel::setFilter(QString filterStr)
{
    filterStr.replace('_', "");
    filterStr.replace('%', "");
    filterStr.replace('*', '%');
    filterStr.replace('?', '_');

    if (!filterStr.startsWith('%'))
    {
        filterStr.prepend('%');
    }

    if (!filterStr.endsWith('%'))
    {
        filterStr.append('%');
    }

    mQuery.bindValue(0, filterStr);
    mQuery.bindValue(1, filterStr);
    mQuery.bindValue(2, filterStr);

    qDebug() << mQuery.exec();
    qDebug() << mQuery.lastError().databaseText();

    clear();
    int row = 0;
    while (mQuery.next())
    {
        QStandardItem *itemId = new QStandardItem;
        QStandardItem *itemName = new QStandardItem;
        QStandardItem *itemNameTr = new QStandardItem;
        QStandardItem *itemRegionName = new QStandardItem;

        itemId->setData(mQuery.value(0).toUInt(), IdRole);
        itemName->setData(mQuery.value(1).toString(), NameRole);
        itemNameTr->setData(mQuery.value(2).toString(), NameTrRole);
        itemRegionName->setData(mQuery.value(3).toString(), RegionRole);

        insertRow(row, QList<QStandardItem *>() << itemId << itemName << itemNameTr << itemRegionName);
        ++row;
    }
}

static QList<int> getTownsIdList(const QJsonDocument &json)
{
    QList<int> townIdList;

    QJsonObject obj = json.object();
    QJsonValue townsVal = obj["towns"];
    if (!townsVal.isArray()) {
        qDebug() << "Json field \"towns\" is not array";
        return townIdList;
    }

    QJsonArray arr = townsVal.toArray();
    auto end = arr.end();

    for (auto it = arr.begin(); it != end; ++it) {
        static const int invalidId = -1;
        const int id = it->toInt(invalidId);
        if (id > invalidId) {
            townIdList.append(id);
        }
    }

    return townIdList;
}

void TownListSqlModel::updateFromServer(ServerApi *api, quint32 leftAttempts)
{
    api->sendRequest("/towns", {},
    [&](ServerApi::HttpStatusCode code, const QByteArray &data, bool timeOut) {
        if (timeOut) {
            if (leftAttempts > 0) {
                emit retryUpdate(api, leftAttempts - 1);
            }
        }

        if (code != ServerApi::HSC_Ok) {
            qDebug() << "Server request error: " << code;
            return;
        }

        QJsonParseError err;
        QJsonDocument json = QJsonDocument::fromJson(data, &err);
        if (err.error != QJsonParseError::NoError) {
            qDebug() << "Server response json parse error: " << err.errorString();
            return;
        }
    });
}
