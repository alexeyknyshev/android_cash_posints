#ifndef LISTSQLMODEL_H
#define LISTSQLMODEL_H

#include <QtGui/QStandardItemModel>

class ServerApi;

class ListSqlModel : public QStandardItemModel
{
    Q_OBJECT

public:
    ListSqlModel(const QString &connectionName, ServerApi *api);

signals:
    void serverDataReceived();

public slots:
    void setFilter(QString filter);

    void updateFromServer();

protected:
    virtual void setFilterImpl(const QString &filter) = 0;
    virtual void updateFromServerImpl(quint32 leftAttempts) = 0;
    virtual int getLastRole() const = 0;

    quint32 getAttemptsCount() const { return mRequestAttemptsCount; }
    void setAttemptsCount(quint32 count) { mRequestAttemptsCount = count; }

    int getRequestBatchSize() const { return mRequestBatchSize; }
    void setRequestBatchSize(quint32 size) { mRequestBatchSize = size; }

    ServerApi *getServerApi() const { return mApi; }

    void setRoleName(int role, const QByteArray &name) const { mRoleNames[role] = name; }

    void emitServerDataReceived()
    { emit serverDataReceived(); }

    /// reimplemented qt methods
    QVariant data(const QModelIndex &item, int role) const override;
    QHash<int, QByteArray> roleNames() const override;

private:
    mutable QHash<int, QByteArray> mRoleNames;

    quint32 mRequestAttemptsCount;
    quint32 mRequestBatchSize;

    ServerApi *mApi;
};

#endif // LISTSQLMODEL_H
