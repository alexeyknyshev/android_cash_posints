#include "listsqlmodel.h"

#define DEFAULT_ATTEMPTS_COUNT 3
#define DEFAULT_BATCH_SIZE 128

ListSqlModel::ListSqlModel(const QString &connectionName, ServerApi *api)
    : mApi(api)
{
    Q_UNUSED(connectionName);
    Q_ASSERT_X(api, "ListSqlModel()", "null ServerApi ptr");

    setAttemptsCount(DEFAULT_ATTEMPTS_COUNT);
    setRequestBatchSize(DEFAULT_BATCH_SIZE);
}

void ListSqlModel::setFilter(QString filter)
{
    filter.replace('_', "");
    filter.replace('%', "");
    filter.replace('*', '%');
    filter.replace('?', '_');

    if (!filter.startsWith('%'))
    {
        filter.prepend('%');
    }

    if (!filter.endsWith('%'))
    {
        filter.append('%');
    }

    setFilterImpl(filter);
}

void ListSqlModel::updateFromServer()
{
    updateFromServerImpl(getAttemptsCount());
}

QVariant ListSqlModel::data(const QModelIndex &item, int role) const
{
    if (role == getLastRole()) {
        return item.row();
    }

    return QStandardItemModel::data(item, role);
}

QHash<int, QByteArray> ListSqlModel::roleNames() const
{
    int lastRole = getLastRole();
    if (!mRoleNames.contains(lastRole)) {
        setRoleName(lastRole, "index");
    }

    return mRoleNames;
}
