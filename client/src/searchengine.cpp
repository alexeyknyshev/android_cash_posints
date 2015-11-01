#include "searchengine.h"

#include "banklistsqlmodel.h"
#include "townlistsqlmodel.h"

#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>
#include <QtCore/QDebug>

SearchEngine::SearchEngine(BankListSqlModel *banksModel,
                           TownListSqlModel *townsModel)
    : mBankListModel(banksModel),
      mTownListModel(townsModel)
{
    setSuggestionsCount(5);
}

void SearchEngine::setFilter(QString filter)
{
    QSqlQuery &townQuery = mTownListModel->getQuery();
    townQuery.bindValue(":name", filter);
    townQuery.bindValue(":name_tr", filter);
    townQuery.bindValue(":region_name", "");
    if (!townQuery.exec()) {
        qWarning() << "SearchEngine::setFilter:" << townQuery.lastError().databaseText();
        return;
    }

    QSqlQuery &bankQuery = mBankListModel->getQuery();
    bankQuery.bindValue(":name", filter);
    bankQuery.bindValue(":licence", "");
    bankQuery.bindValue(":name_tr", filter);
    bankQuery.bindValue(":town", "");
    bankQuery.bindValue(":tel", "");
    if (!bankQuery.exec()) {
        qWarning() << "SearchEngine::setFilter:" << bankQuery.lastError().databaseText();
        return;
    }

    QList<QStandardItem *> sugItemList;
    while (townQuery.next() && sugItemList.size() <= mSuggestionsCount) {
        QStandardItem *item = new QStandardItem;
//        item->setData();
        sugItemList.append(item);
    }
}
