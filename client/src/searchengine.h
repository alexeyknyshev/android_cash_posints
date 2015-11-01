#ifndef SEARCHENGINE_H
#define SEARCHENGINE_H

#include <QtGui/QStandardItemModel>

class BankListSqlModel;
class TownListSqlModel;

class SearchEngine : public QStandardItemModel
{
    enum Roles {
        IdRole = Qt::UserRole,
        NameRole,
        NameTrRole,
        TownNameRole,

        RoleLasts
    };

public:
    SearchEngine(BankListSqlModel *banksModel,
                 TownListSqlModel *townsModel);

public slots:
    void setFilter(QString filter);
    void setSuggestionsCount(int count) { mSuggestionsCount = count; }

private:
    BankListSqlModel *mBankListModel;
    TownListSqlModel *mTownListModel;

    int mSuggestionsCount;
};

#endif // SEARCHENGINE_H
